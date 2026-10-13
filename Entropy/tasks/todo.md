# Task: KeepCrypt milestones M0 to M3

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
      yet; `main` is unprotected today. (Changed 2026-10-10: ruleset 24833307 protects `main`, with 0 approvals; M1
      Review, "M1: the owner's answers applied".)
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

### Raised by the review of commits 2-5 (standing approval applied 2026-10-10; confirmed by the owner 2026-10-10)
Applied by the agent, not an answer from the owner: the owner's standing approval of the Q1-Q12 recommendations ("I
approve, do it", 2026-10-09) was applied on 2026-10-10 to Q13 (all five doc edits, as recommended) and Q14 (both
gate changes, as recommended). The owner had not answered Q13 or Q14 directly until 2026-10-10, when the owner
confirmed both (owner item 2). The owner may veto any item; a veto reverts that item in its own reviewed commit.
Q13's edits landed as one docs-only commit (c40a2e3) before commit 8 ("Q13 docs" in "Commit order on `m1-core`");
Q14's two gate changes stay as committed in f732c98.
- [x] The owner confirms Q13 (a)-(e) and Q14 (a)-(b) explicitly, recorded here with a date, before the M1 gate
      (review fix after commit 10). Answered 2026-10-10: "approve all" (owner item 2, "M1: the owner's answers")
      confirms all five doc edits and both gate changes as applied; nothing is reverted.

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

### Raised by the review of commits 11-15 (answered 2026-10-10)
At commit 11 the agent replaced a value that the approved plan pins. Commits 12-15 built on the replacement, and no
owner had approved it until 2026-10-10 (owner item 3). It is not covered by the standing approval of Q1-Q12.
- [x] The owner answers Q15, recorded here with a date, before the M1 gate (review fix after commit 15). Answered
      2026-10-10 (owner item 3): the table-text definition, the digest `fd75c236...` and the reworded proof are
      approved.

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
    own reviewed commit. Until the owner answers, `fd75c236...` is the agent's value, not an approved one. (Approved
    2026-10-10.)

### Raised by the review of commits 19-21 (answered 2026-10-10)
Neither is covered by the standing approval of Q1-Q12; the agent does not act on either until the owner answers.
- [x] **The age CLI's files.** Plan group 8 says `scripts/age-interop.py --generate` writes
      `vectors/age/age_cli_written.json` with Ubuntu's age 1.1.1-1ubuntu0.24.04.3; commit 19 wrote it with Homebrew
      age 1.3.2 (`tool_version` `v1.3.2`), the only CLI installable on this Mac, and recorded that as a deviation
      without the owner's approval. Please either approve the 1.3.2 substitution, or have the files regenerated with
      Ubuntu's 1.1.1 (for example by the commit 27 CI job) and committed in a `verify:` commit. Until then the
      group 8 proof "the age 1.1.1 files decrypt" and the Verification item "core reads age 1.1.1 files" stay
      unticked. Either way, the commit 27 `age-interop` job runs `scripts/age-interop.py --core` against 1.1.1, so
      in CI core decrypts files 1.1.1 has just written and 1.1.1 decrypts core's (the default mode reads 1.1.1's
      output only with verify.py's reader). Recorded 2026-10-10, review fix after commit 21. Answered 2026-10-10
      (owner item 7): the 1.3.2 substitution is approved, so the committed files stay as written. The CI job still
      runs `--core` against Ubuntu's 1.1.1 (Verification "Backup").
- [x] **Q1 (iii)'s upstream issue.** The owner approved "accept that scrypt 0.12 never zeroizes its 256 MiB working
      buffer, and file an upstream issue". The acceptance is applied (`backup/age.rs`); the issue is not filed, and
      filing it posts in public, so it waits for the owner to file it or to say go ahead. Record the link here once
      it exists. Recorded 2026-10-10, review fix after commit 21. Answered 2026-10-10 (owner item 8, an explicit
      yes): filed under the owner's account as https://github.com/RustCrypto/password-hashes/issues/938 ("scrypt:
      zeroize the B, V and T buffers before freeing them"), open.

### Raised by the review of commits 22-25 (answered 2026-10-10)
Commit 25 recorded a change to an approved plan item as a done deviation, not as a question. The standing approval
of Q1-Q12 does not cover it, so it waited for the owner (answered 2026-10-10, owner item 9).
- [x] **tests/vectors.rs and the full vector sets (plan group 10).** The plan says tests/vectors.rs runs the full
      sets: 24 BIP39 seeds, 26 CCTV files, 3 seal vectors, 2,048 braille entries, watchonly.json, kcr.json,
      backup.json and rolls.json. As built, tests/vectors.rs runs only what the public API reaches, because secrets
      have no public constructor (CLAUDE.md rule 5); the rest runs in the unit tests of each module, from the same
      files (group 10, "As built at commit 25"). Two parts differ from the plan:
      - (a) Placement: the CCTV files, seal.json's vectors 2 and 3, the 2,048 braille entries and watchonly.json
        run as unit tests, not in tests/vectors.rs.
      - (b) BIP39: core runs 16 of the 24 entries, the 12- and 24-word ones (the words, the TREZOR seed derived
        through `passphrase_seed_into`, and the master fingerprint). The 8 entries with 18 words are a length core
        never makes, so only their words are checked (the Bip39 KAT, through the bip39 crate, and verify.py), and
        nothing recomputes their seeds.
      Recommended: approve both as built. Otherwise: (a) a public test-only constructor behind `test-sources`
      would let tests/vectors.rs reach the secret-holding sets; (b) a stdlib PBKDF2 check in verify.py can
      recompute all 24 seeds, in a `verify:` commit. Until this is answered, the Verification item "All vectors
      pass" stays unticked. Recorded 2026-10-10, review fix after commit 25. Answered 2026-10-10 (owner item 9):
      (a) and (b) are approved as built.

### Raised by the review of the owner-item commits (2026-10-10; item 14 answered 2026-10-11, item 13 pending, low)
Neither blocks the M1 gate. Both are items 13 and 14 under "M1: new open owner items" in Review.
- [ ] **The seed-pipeline figure.** `docs/img/seed-pipeline.png` still reads "50 rolls give 129 bits; 99 give 256".
      The repo holds no source for it. 6ba465c notes the rounding in the sentence under the figure. A redraw needs
      the owner's source file, or approval to redraw it.
- [x] **The 99-roll minimum after a wipe.** Only a `Wiped` carries the 99-roll minimum after a collision, and only a
      check leaves one. So an error, the Pi's idle wipe, the phones' background or screenshot wipe, or an app kill in
      the restarted session leads to `Session::new` at the normal minimum. seal-watchonly-braille.md "Add fresh
      entropy" now states that exception (dc53b8f). Recommended: in M3, a core exit on the pre-Ready states that wipes
      and returns a `Wiped` keeping the flag, for the shells' timeout and capture wipes. Otherwise: keep the
      documented exception. Answered 2026-10-11 (M3 Q26 (C), "approve all"): instead of a new exit,
      `Wiped::restart(&self, ..)` borrows, so the Pi keeps the last `Wiped` until a check passes or the user skips, and
      restarts from it after the idle wipe (7299e27); errors halt the Pi (Q25). seal-watchonly-braille.md "Add fresh
      entropy" now says a timeout does not lower the minimum, replacing dc53b8f's exception (c306bc2). The phones keep
      their `Wiped` the same way in M5 and M6.

### Needed before M2 code (Q16-Q24, answered 2026-10-10)
**Owner's answer (2026-10-10): "approve all".** Every recommendation below is approved as written: Q16 (a) the split
into the shipped verify.py and the repo-only vectorgen.py, and (b) provenance naming vectorgen.py with
age_cli_written.json unchanged; Q17 (A) vectors/agreement.json committed and replayed by core; Q18 the plan's case mix;
Q19 (a)-(c) the doc edits; Q20 the rule 5 handling; Q21 the roll-string rules; Q22 re-checks move to M9 (reversing
M1 Q3 (ii)'s stated reason; the Ed25519, Merkle and .kcr/KCP1 verifiers stay in verify.py, unused until M9); Q23 the
Python networking and clipboard patterns; Q24 the age interop files delivered in M1 and agreement.json as M2's
KeepCrypt vectors. The questions as asked:

Please answer these before any M2 code is written. Each gives a recommendation and says what changes otherwise. Every
M2 commit touches CODEOWNERS paths (tools/verify, vectors, core and its Cargo.toml, scripts, .github, CLAUDE.md,
docs), so the whole PR needs your review, as M1's did.

16. **Split the shipped verifier from a repo-only generator (rules 8 and 10), and keep provenance true.**
    Recommended:
    - (a) two files in `tools/verify/`, split by one rule (plan group 1):
      - `verify.py` ships: every published computation and reader, the user commands and the embedded known answers.
        It is the file whose SHA-256 the release notes print;
      - `vectorgen.py` never ships: the generators and `--write-*` modes; checks 1-11 with the new 12 and 13; the
        label keys and test public key; the `.kcr`/KCP1 builders; the age vector builder; and the Coldcard runner.
      - Why: a release copy of today's file fails rule 10's scan (label 855, test public key 889, signer 2636-2660).
        It breaks rule 8, because `write_vectors` writes seven JSON files and its checks read JSON, Markdown and a PDF.
        And it cannot check itself without the repo.
      - Cost: the move is one commit, proven by byte-identical vectors. It changes age-interop.py's loader (line 58),
        canaries' tamper command, the two CI selftest steps, CLAUDE.md Commands and build-plan.md:60 (Q19 (c));
    - (b) provenance, in the commit after the move:
      - the seven files' `description` strings, SOURCES.md and six core comment lines name vectorgen.py, proven by
        "only the description changed";
      - `vectors/age/age_cli_written.json` keeps its bytes and hash row. SOURCES.md records that its sentence
        "verify.py --selftest reads their armor and headers (check 11)" now means vectorgen.py check 11.
    Otherwise:
    - (a) keep one file and decide the release form in M7: either a strip step (the shipped file then differs from the
      reviewed one), or a recorded rule 8 and rule 10 exception for verify.py. M2 would still add the lone-copy check,
      and no provenance edit is needed;
    - (b) regenerate age_cli_written.json with the approved age 1.3.2 so its text names vectorgen.py. That means new
      random file keys and salts, a new hash row, and age-interop re-run in both directions.
17. **How the 1,000 agreement cases are produced and compared.**
    Recommended: (A) vectorgen writes them, the file is committed, and core replays it.
    - `vectors/agreement.json`, one case per line, about 2-2.5 MB (braille.json, the largest today, is 524 KB);
    - `core/tests/agreement.rs` replays every case through the public session API under `test-sources`;
    - check 13 regenerates the file byte for byte on both Pythons.
    This is M1's "vectors first" pattern and fits rule 12's wording ("use the vectors in `vectors/` only"). It keeps
    Rust out of the Python jobs, so it needs no new CI job, and a failure names the case and field.
    Otherwise:
    - (A2) commit the inputs and one SHA-256 of each case's outputs (about 0.6 MB). This needs a canonical output text
      defined identically in Rust and Python, and a failure no longer says which field differs;
    - (B) an ignored core test writes cases into a directory that vectorgen reads. Nothing is committed, but every job
      running it needs cargo and Python (the macOS py39 job has no toolchain), and the repo keeps no baseline.
18. **What the cases cover, and their cost.**
    Recommended: the plan's mix (group 5):
    - 1,000 ceremonies, 8 combinations × 125:
      - Skip and Check, some with a wrong first code (the next valid symbol, so core must say `WrongCode`);
      - extras in every mode, undo, Pi hwrng chunking across the 1,024-sample boundary, and roll counts from the
        minimum to 256;
      - 8 restarts after a "Match found" discard, with core's collision report compared;
    - 28 refusal cases: one roll short, a 257th roll, a face of 0 or 7, and 4 restarts with 98 rolls for 12 words;
    - compared: C, D, the seed bits (through the words), the words, the full seal, n, G accepted by core, the URLs, the
      grouped seal code, every insert token, and `seal_from_mnemonic`;
    - Coldcard's scripts on about 70 dice-only strings, which keeps short the selftest that the canaries repeat;
    - no fingerprint, first address, watch-only export or backup.
    Otherwise:
    - (i) add the fingerprint and first address. verify.py's affine secp256k1 costs about 35 ms per multiply, so this
      needs a Jacobian rewrite first (29 times faster in a scratch copy, same keys on 50 test keys, watchonly.json
      byte-equal). Without it, every selftest grows by about 35 s for the fingerprints alone, and by 2-3 minutes with
      the first addresses;
    - (ii) add backup cases. Core takes 1.26 s per case at work factor 18, and vectorgen can rebuild them only where
      `hashlib.scrypt` exists, which `/usr/bin/python3` 3.9 lacks;
    - (iii) run Coldcard's scripts on all of about 510 dice-only strings: about 15 s more per selftest on 3.9, and 10
      times that in `gates`.
19. **Doc edits** (one commit, no code).
    Recommended:
    - (a) pi-firmware.md step 14 and mobile-apps.md step 16: "D is shown as 16 groups of 4 hex characters, like C".
      No doc says how D is shown. With this edit the verifier reads C and D with one rule, and M3, M5 and M6 show D
      that way;
    - (b) design.md:242, step 2: "record C before the first roll, then D and the rolls (mixed mode), or only the rolls
      (dice-only)", in place of "record D or the rolls", matching mobile-apps.md:186;
    - (c) with Q16, build-plan.md:60's layout line: `verify/` holds `verify.py` (the offline verifier; ships as one
      file) and `vectorgen.py` (vectors and the repo self-test; never ships), Python 3 standard library only.
    Otherwise: for (a), show D as 24 BIP39 words, like Coldcard's device value (design.md:229). The verifier then parses
    words for D, and the shells follow. Or leave (a) open and let M3 decide. (b) and (c) stay as they are.
20. **Rule 5 inside a verification run.**
    Recommended:
    - input only at prompts; nothing from arguments, the environment or a file;
    - on a terminal, C, D and each line of rolls are read without echo (getpass, prompts on stderr):
      - C is then printed back in 16 groups of 4 for proofreading. D and the rolls are never printed, only their counts;
      - a mistyped D shows as "D does not match C", and a mistyped roll as different words;
      - reading C hidden too matters: getpass drops input typed ahead of its prompt, so a paste of C, D and the rolls
        at once is dropped rather than shown by the terminal;
    - piped input still works, for tests and scripts, but prints a notice to clear shell history. The guide says never
      to use `echo ... |`, which Coldcard's rolls.py documents;
    - the run prints the seed bits, the words with their braille inserts, the seal and the seal code, because comparing
      them with the device is the point of the run (design.md step 2). They appear under the "never fund it" banner;
    - errors name the field and position, never the input; there is no traceback; and the file runs only under
      `python3 -I`;
    - tested in a pseudo-terminal (check 12 (f)) as well as through pipes.
    Otherwise:
    - (i) echo D and the rolls as typed: easier to proofread 256 digits, but they stay in the scrollback;
    - (ii) a compare mode: the user types the device's words and gets match or mismatch, so the words are never printed.
      This puts typed words into the verifier;
    - (iii) allow runs without `-I`, with a warning;
    - (iv) echo C as typed: simpler, but a paste of all three fields at the C prompt then shows D and the rolls.
21. **Roll strings.**
    Recommended:
    - strip each line as rolls.py does, then accept only the ASCII digits 1-6. An internal space is refused, not
      removed, because removing it would change the hash compared with rolls.py. Lines typed separately are joined;
    - `mixed` refuses a count outside [50 or 99, 256] and prints no words (exit 1), since no honest KeepCrypt device
      finishes such a run;
    - `dice` computes any non-empty count, with a warning outside that range, as rolls.py does. So Coldcard runs can be
      checked, including Coldcard's published 6-roll `123456`. The agreement expects core to refuse these counts;
    - the 99-roll minimum after "Match found" cannot be seen from C, D and the rolls, so the verifier uses 50 or 99 by
      length. Its notes say that 50-98 rolls for 12 words is valid only for a first ceremony. The agreement records the
      4 restarts with 98 rolls as a known divergence: core refuses them and the verifier computes.
    Otherwise:
    - (a) refuse outside the range in both modes, so short Coldcard runs cannot be checked;
    - (b) warn in both modes, so a mixed run that no honest device produces still prints words;
    - (c) add an `--after-collision` flag to `mixed` that raises the minimum to 99. It closes the divergence only when
      the user remembers to pass it.
22. **Re-checking a real wallet: not in M2. This reverses the reason you approved in M1.**
    Recommended: M2's verifier takes no seed words, backup or snapshot, and re-checks land in M9
    (seal-watchonly-braille.md "Re-checking an existing wallet").
    - This reverses M1's stated plan. Q3 (ii) put Ed25519 in verify.py because "M2 needs this for re-checks"
      (todo.md:90-91), and M0's plan said M2 "grows it into the full verifier" (todo.md:604). Why now:
      - a snapshot or KCP1 lookup needs the pinned registry key, and release builds pin none until M9 (Q3 (iii));
      - the online URL points at `registry.invalid` until M9, so a re-check now ends at a URL that looks nothing up;
      - backups raise their own question then: `/usr/bin/python3` 3.9 has no `hashlib.scrypt`, and the pure-Python
        path at work factor 18 took about 3 minutes and 2.5 GB here;
      - so no real seed is typed into the verifier in M2.
    - The Ed25519, Merkle and `.kcr`/KCP1 verification stays in the shipped verify.py, unused by any M2 command, because
      M9 needs it and vectorgen's checks 8 and 10 keep exercising it.
    Otherwise:
    - (a) keep part of the M1 expectation now, which needs neither the key nor the origin: `seal --words N`. The words
      are read without echo (four-letter prefixes accepted, checksum required), and only public seal values are printed,
      with the placeholder URL. The user can compare the Seal ID with the braille and the device; the lookup itself
      still waits for M9;
    - (b) also `backup FILE.age`: at most 8 KiB, the passphrase read without echo, the fingerprint and seal printed. It
      would refuse work factors above 14 without `hashlib.scrypt`, unless `scrypt_pure` is rewritten on a flat table
      (about 256 MiB, still minutes);
    - (c) `recheck --snapshot FILE.kcr` now, with no key pinned: every snapshot is refused until M9, and the path is
      tested in vectorgen with the test key. A user-supplied key is not offered: a key from a phishing page plus a
      forged snapshot could show "count 1";
    - (d) move the unused Ed25519, Merkle and `.kcr`/KCP1 verifiers to vectorgen until M9, so the shipped file holds
      only what its commands run. They move back in M9.
23. **Python networking and clipboard patterns in the banned-API gate** (a `scripts/` change).
    Recommended: add them (plan group 2). Today nothing machine-checks that Python code stays offline, though design.md
    has users run verify.py on the offline computer of a run. Check 12 adds a stronger guard for verify.py alone,
    inside vectorgen: an import and module-attribute allowlist, and audited runs.
    Otherwise: check 12 only, so vectorgen and `scripts/` could import network modules unnoticed.
24. **What "KeepCrypt vectors" and "age interop files" mean for M2.**
    Recommended:
    - the age interop files are already delivered. M1 committed `vectors/age/age_cli_written.json` (age 1.3.2,
      approved), and the `age-interop (age 1.1.1)` job checks both directions live at work factor 18, core included
      (build-plan.md:253, "and the reverse");
    - M2's KeepCrypt vectors are `vectors/agreement.json`.
    Otherwise: also commit core-written backups as `vectors/age/core_written.json`, written under a stub, rebuilt by
    vectorgen where `hashlib.scrypt` exists, and decrypted by age in `age-interop`. On Python 3.9, vectorgen could check
    everything but the stanza body.

### Needed before M3 code (Q25-Q34, answered 2026-10-11)
**Owner's answer (2026-10-11): "approve all".** Every recommendation below is approved as written: Q25 any runtime
failure halts until a power cycle; Q26 (C) the borrowing `Wiped::restart(&self, ..)`; Q27 (a) `game_random` with its
limits, (b) the games in the firmware's one process with no path to the session, (c) Snake in M3 and Tetris later;
Q28 (a)-(e) embedded-graphics 0.8.2 with its 7 crates, qrcodegen-no-heap 1.8.1, no simulator crate (pi/sim's own PNG
writer), the new edges to vetted crates, and 6 vet exemptions plus 3 imports; Q29 the Protected and Public screen
classes with the privacy gate, the 30 s cover, the 9-minute warning and the 10-minute wipe; Q30 (a)-(h) the
simulator's inputs, captures and live mode; Q31 (a)-(i) CI and gates, including the pre-approved opt-level fallback;
Q32 (a)-(c) the key map, `from_first_four` and printable-ASCII BIP39 passphrases; Q33 (a)-(m) the flow details; Q34
the doc edits (CLAUDE.md rule 1 names `game_random`), with owner item 13 left open. The owner was also told that a
planning agent's `cargo tree` had downloaded the 8 candidate crate archives into cargo's cache (nothing built). The
questions as asked:

Please answer these before any M3 code is written. Each gives a recommendation first and says what changes otherwise.
Every M3 commit except the pi/sim-only ones touches CODEOWNERS paths (core, pi/app, every Cargo.toml, Cargo.lock,
supply-chain, scripts, .github, docs, CLAUDE.md), so the whole PR needs your review, as M1's and M2's did.

25. **Runtime failures halt the device (rule 3; design.md:178; pi-firmware.md:75, :82).**
    Recommended: the red stop screen of boot (step 1) also ends any later failure, until a power cycle.
    - These halt: every error that ended a session; every known-answer-test, entropy-source, health-test, internal or
      export-self-check error from any call (core's game call included); every display, button or hwrng fault.
    - Only refusals of what the user or a stick supplied return to their screen: a wrong go-ahead code, a read-back
      mismatch, a wrong backup passphrase or unrecognised entry, an empty BIP39 passphrase, snapshot refusals, and USB
      faults.
    - A power cycle reruns the boot self-test and the hwrng boot test before any new seed.
    - Why: design.md:178 says any failure halts seed generation with no degraded mode, and core's own contract says such
      an error means no seed can be made. Returning to Home would let an intermittently failing hwrng pass on a second
      try, or let a dice-only seed follow straight after the hwrng failed.
    - Cost: a power cycle forgets the 99-roll flag (as power-off does today), and the scenario `runtime_stop` shows it.
    - Doc edits: pi-firmware.md:75 and :82; seal-watchonly-braille.md:146 (with Q26).

    Otherwise:
    - Back to Home after any error, keeping the flag (the earlier draft).
    - Halt only on known-answer-test and health-test errors; Home for the rest.

26. **Owner item 14: keep the 99-roll minimum through the idle wipe (rule 6; todo.md:456-461).**
    Recommended: (C) `Wiped::restart(&self, len, mode)` borrows the `Wiped` instead of consuming it (wiped.rs:121 takes
    `self` today, and so does `restart_with_stub`).
    - How it works: the Pi keeps the last `Wiped` until a check passes or the user skips, and replaces it with each
      newer one. If the 10-minute idle wipe ends the restarted ceremony, the next restart is still at 99.
    - After Q25, the idle wipe is the only in-RAM end of a session that would lose the flag (errors halt, and Stop and
      Cannot check already keep it).
    - Why (C): one signature change, no new trait; a shell bug can only keep 99 longer; it suits UniFFI's shared
      objects in M5 and M6.
    - What it costs: after a collision, the kept `Wiped` holds the destroyed seed's seal code (wiped on drop) until a
      check passes, the user skips, or a halt or power cycle. It is never shown again after the collision-report QR.
    - One compile-fail fixture changes: `wiped_holds_no_secret.stderr` quotes the `restart` signature in a rustc hint,
      so it is regenerated and its diff touches only that line and its underline.
    - Doc edits: seal-watchonly-braille.md:146 and build-plan.md:153. The module docs at session.rs:10-15 and
      wiped.rs:9-18 change in the same core commit.

    Otherwise:
    - (A) A sealed `PreReady` trait with `fn wipe(self) -> Wiped`, which the idle wipe calls, plus a fixture showing
      `Ready` has none. After Q25 it covers the same cases as (C), at the cost of a new trait and fixture.
    - Keep the documented exception (dc53b8f): the idle wipe drops back to the normal minimum.

27. **Core's game-randomness call, and the game (rule 1; todo.md:629-633; design.md:264).**
    (a) Recommended:
    - `pub fn game_random(buf: &mut [u8]) -> Result<(), CoreError>` in `core/src/source.rs`, re-exported from lib.rs.
      - Its body is one `Source::Os.fill(buf)` (source.rs:132): the exact-length OS path.
      - It takes no session, touches no pool, has no stub twin, and reads the real OS in every build.
      - The bytes are plain, not zeroizing, because games draw them.
      - Its doc comment and CLAUDE.md rule 1 say it is never used for dice, D, nonces, passphrases or any pool input.
    - Its one error halts the device (Q25), because the commitment reads the same OS source.
    - In pi/app only `games/mod.rs` names it, and a grep holds that.
    - The name goes into build-plan.md:91 and :202-204, pi-firmware.md:68 and :103, mobile-apps.md:142,
      seal-watchonly-braille.md:292, and CLAUDE.md:47 (rule 1): approve my CLAUDE.md edit, or make it yourself.

    Otherwise: another name; an error closes only the game.

    (b) Recommended: the games run in the firmware's one process. design.md:264 says they run "in a separate process
    that can only add uncredited bytes to the pool", while pi-firmware.md:43, :50 and :58 describe one binary with one
    respawn entry.
    - In one process the games still hold no session and no pool handle: they take bytes only from the game call, and
      only the ceremony loop forwards key timing to the pool. That is stricter than pi-firmware.md:69, which hands the
      games an `ExtraSink`.
    - A grep keeps the session, `add_extra` and clocks out of the games' code.
    - design.md:264 changes to match.

    Otherwise: a separate game process. It needs a second binary, a pipe for key timing, a second respawn entry (or a
    spawn from keepcrypt-pi) and its own scan, and it is not planned here.

    (c) Recommended: M3 ships Snake only, which meets the gate's "waiting-screen game". Tetris (with the optional braille
    letters of seal-watchonly-braille.md:292) is not in M3 and gets a milestone when you choose; the docs keep it as
    planned, and pi-firmware.md says "Snake (Tetris later)".

    Otherwise: both games in M3; or Tetris with the phones (M5, M6), which plan both games (mobile-apps.md:142).

28. **New crates, the QR encoder and the simulator's display (rule 11; build-plan.md:76; pi-firmware.md:62, :70).**
    Recommended:
    - (a) `embedded-graphics 0.8.2` in pi/app (named in build-plan.md:76). It brings 7 more crates (table under "New
      dependencies"); autocfg is held at 1.5.0, the version the vet imports cover.
    - (b) `qrcodegen-no-heap 1.8.1` (MIT, no dependencies, same author and API as the docs' `qrcodegen`). It encodes
      into buffers that pi/app owns and wipes after drawing, which matters because the registration and collision QRs
      carry seal codes. 1.8.0 was yanked the day 1.8.1 came out; the vet note records it. Added to build-plan.md:76;
      pi-firmware.md:70 renamed.
    - (c) No `embedded-graphics-simulator`. pi/app draws into its own `Frame`, exactly the pixels M4 sends to the
      ST7789, and pi/sim writes PNGs with about 80 lines of its own (stored deflate, CRC-32, Adler-32). Headless: no
      native library on this Mac or in CI. The encoder is deterministic; screens that show fresh OS bytes (the check
      nonce, C, D, the backup passphrase, Snake's food) differ from run to run. build-plan.md:76 and pi-firmware.md:62
      change to match.
    - (d) New edges to crates already in Cargo.lock and vetted: pi/app → `zeroize`; pi/sim → `keepcrypt-core` (no
      features; without it `-p keepcrypt-pi-sim --features keepcrypt-core/test-registry` fails to resolve); pi/sim
      dev-dependencies → `sha2` (safe-to-deploy) and `serde_json` (safe-to-run only, so a dev-dependency and nothing
      more).
    - (e) cargo vet: 6 exemptions and 3 imported audits. No deny.toml change.

    Otherwise:
    - `qrcodegen 1.8.0`, whose freed `Vec<bool>` keeps the QR's modules in memory (recorded with M7's residuals).
    - `embedded-graphics-simulator 0.8.0` without SDL: 18 more crates, flate2 held at 1.1.5 to keep zlib-rs out of the
      lock, and at least 4 more exemptions. An SDL window also needs SDL2 on this Mac and in CI, Zlib on the licence
      list, and lazy_static 1.5.1, which is inside the cool-off.

29. **Protected screens and idle on the Pi (rule 5; pi-firmware.md:75; mobile-apps.md:111-113, :166).**
    Recommended: two screen classes, Protected and Public.
    - Protected: the phones' list (mobile-apps.md:111: backup passphrase, reveal-D, seal code, registration and
      watch-only QR screens) plus the words and every entry grid that holds a secret. On the Pi that is: words in
      insert view and overview (ceremony and "Check a backup"); read-back entry and mismatch; the backup passphrase,
      its confirm and its wrong-pick screen; BIP39 passphrase entry and backup-passphrase entry; D; the registration
      QR; the collision-report QR (the destroyed seed's seal code); the account and descriptor QRs.
    - Entering a Protected screen from a Public one passes one privacy gate ("No person or camera can see this
      screen"), like the phones' "I'm alone, show words".
    - After 30 s without input, a Protected screen is covered. The first press only uncovers it, and the session stays
      (mobile-apps.md:112), so slow punching or scanning is never cut short.
    - At 9 minutes without input, a warning appears on any screen while a session or a checked backup is held.
    - At 10 minutes, the wipe (pi-firmware.md:75). The kept `Wiped` (Q26) and a loaded snapshot survive it.
    - The wallet summary (step 10), the watch-only summary, the dice screen and the check QR (T and a nonce) stay
      Public, as on the phones.

    Otherwise: only the documented 10-minute wipe, with no cover and no gate; or Protected for the words alone.

30. **The simulator's inputs, captures and live mode (rules 5, 8, 10, 12).**
    Recommended:
    - (a) The simulated hwrng is the counting stream (i mod 256, without end) for normal runs. The stop runs use
      keepcrypt.json's 2,048-byte `run-of-6-startup` and `apt-62-startup` at boot and `run-of-6-continuous` in step 4,
      read from the vectors by the tests and pinned to core's recorded verdicts. They are counters, not PRNGs. The
      commitment's 64 OS bytes, the nonce and the backup secrets stay real.
    - (b) No pi build ever uses `test-sources`. `test-registry` is switched on only from the command line, with `-p`.
    - (c) Repeatable words come only from dice-only runs on keepcrypt.json's public roll strings: `coldcard-50`
      (kcr.json `dice-50-words12`, in snapshot `with-dice-50`) and `coldcard-99` (`dice-99-words12` and
      `dice-99-words24`).
    - (d) pi/sim's tests compute G from the check QR's `t` and `n`, using sha2 and Crockford, after checking that the
      drawn QR encodes that payload. release_probe.rs:112 already does this; it is pinned to CLAUDE.md's `CF94-BCAJ`.
      Core's `go_ahead_code` stays crate-private, and verify.py still issues no code.
    - (e) The carried verify.py tie (todo.md:3491-3492) is a Mixed run in the release configuration: C and D read from
      the drawn screens' models, the rolls from the script, piped into `verify.py mixed`, which must exit 0. The words
      and Seal ID are compared in memory, never printed.
    - (f) `Display::present` also receives the screen model, and the frame is always drawn from that model by one
      renderer. The device ignores the model; the tests read it in memory and print only screen ids.
    - (g) Captures come only from one ignored test, `capture_set`, run on request: every scenario in order, into
      per-configuration folders under cargo's `target/tmp/` (gitignored), cleared first. Protected frames of Mixed
      runs become a grey placeholder; `reveal-d` is shown once as a specimen drawn from the public D `d-00-1f`. The
      index lists each PNG's SHA-256. Never committed, never uploaded by CI. I send you the set, zipped, with the
      commit, a clean-tree check and the zip's SHA-256 under Review, and ask you to scan every QR with a phone.
    - (h) `live` mode writes every Protected frame as the placeholder, in every run; shows "SIMULATOR · NOT FOR REAL
      FUNDS" on every screen; and reads no file (its RAM stick starts empty).

    Otherwise:
    - (e) A pi/app ceremony test under `--features keepcrypt-core/test-sources`: a repeatable Mixed seed, but against
      todo.md:2298-2299 and a new CI step.
    - (d) A core `test-registry` function that issues codes.
    - (g) Capture everything; or a CI artifact upload, which needs a new pinned action and lets anyone with read access
      download throwaway words.
    - (h) Live mode with `--stick FILE` and unredacted frames, only for vector runs.

31. **CI and gates (required checks unchanged).**
    Recommended:
    - (a) No new job. Ruleset 24833307's 14 required check runs are unchanged.
    - (b) `test` gains: the simulator tests in the registry configuration; a release build of the test-registry
      simulator for the host (with the cross job's getrandom cfg), scanned by `banned-api-check.sh --artifact`. It must
      report exactly the registry marker, the simulator marker and the test key, and no stub marker
      (todo.md:2298-2299). The scan shows no foreign RNG crate symbol; it cannot see std's OS-seeded hashing, which
      (e) covers.
    - (c) `cross`: on the ARM leg, also build pi/app's release rlib and scan it, which must be clean (todo.md:982).
      release_probe gains `game_random`. No `keepcrypt-pi` binary is linked or scanned until M4.
    - (d) A simulator marker, `KC_SIMULATOR_DO_NOT_SHIP`, embedded in the simulator's fake hwrng and stick the way core
      embeds its test markers, and added to the artifact scan's marker list with a selftest case. M4's image scan then
      fails on any simulator code (pi-firmware.md:76).
    - (e) `gates`: new banned-API rules, each with hit and clean fixtures:
      - a Shell category: the games' code names no session, `add_extra`, `add_hw_samples`, ceremony or clock;
        `game_random` is named only in core and under `pi/app/src/games/`; `Session::new` appears once in pi/app;
      - std's OS-seeded hashing (`HashMap`, `HashSet`, `RandomState`, `DefaultHasher`, `hash_one`,
        `BuildHasherDefault`) banned in core/src, ffi/src and pi/app/src, with core/src/pool.rs's one test switched to
        `BTreeSet`;
      - the `#![forbid(unsafe_code)]` line check extended to pi/app's lib.rs and main.rs, with the selftest's `fresh()`
        and fixtures updated.
      No new canary, so the count stays at 61.
    - (f) Budgets: `gates` took 8m07s of its 10 minutes and pi/app grows from 1 line to the whole UI, which the
      real-crate canaries lint 8 times. If the job exceeds 10 minutes, the budget becomes 12; the job timeout stays 30.
      `test` grows by at most 6 minutes.
    - (g) Fallback, approved now so I can use it if group 7's measurement says so: `opt-level = 1` for keepcrypt-pi and
      keepcrypt-pi-sim in dev and test builds, with the canaries' pinned `[profile]` updated in the same commit.
      Coverage is core only, so it is unaffected.
    - (h) The carried banned-API routes (todo.md:5314-5317) land in the scripts commit: `import logging.config` and
      `multiprocessing.managers`; a dotted import ending in a banned name (`gevent.socket`); tkinter's `selection_own`
      and `tk.call('clipboard', ...)`; PowerShell `gcb`/`scb`, as whole words, only in `.ps1`/`.psm1` files and shell
      lines; JXA's `theClipboard`; pandas' `clipboard_set`.
    - (i) `#![forbid(unsafe_code)]` in pi/app and pi/sim; M4 asks before adding any `unsafe` for mlockall or mount.
      pi/sim denies `print_stdout`, `print_stderr` and `dbg_macro`, with one allowed print site in the bin and one in
      the tests. CODEOWNERS adds `/Entropy/pi/sim/`, because its tests are the gate's evidence.

    Otherwise: a separate simulator job (a ruleset change); no simulator marker until M4; no hash ban (std's hashing
    then rests on review); (h) moves to M7 with verify.py's release scan; no profile fallback (a slow `test` job stops
    the milestone for re-planning).

32. **Buttons and typing on the Pi (pi-firmware.md defines only the dice keys, :87, and the word keys, :89).**
    (a) Recommended: one press is one event (no auto-repeat, no type-ahead filter), and a footer names every key's
    action on every screen.

    | Screen kind | Up / Down | Left / Right | Press | KEY1 | KEY2 | KEY3 |
    | --- | --- | --- | --- | --- | --- | --- |
    | Menus, offers | move | - | select | back, only where nothing is lost | - | - |
    | Dice | pick 1-6 (blank after each confirm) | - | confirm | undo | - | Done, only at the minimum |
    | Words | - | - | read-back, on the last insert (back to entry when reviewing a mismatch) | overview on/off | previous | next |
    | Entry grids | cursor | cursor | type | delete | - | done |
    | Read-back mismatch | - | - | re-enter | show the insert | - | - |
    | Snake | steer | steer | play again, after a round ends | leave | - | - |
    | QR and info pages | - | - | continue | back | previous page | next page |

    - The entry grids: go-ahead code, the 32 Crockford symbols in 8×4; read-back and backup words, a-z plus "blank" in
      7×4; BIP39 passphrase, printable ASCII in three 8×4 pages.
    - Confirm is disabled at 256 rolls. One-way choices (Skip, Match found, Cannot check) each take a confirm screen.
    - Amended by the owner on 2026-10-13, during M3 ("Raised by stage C's review during M3", below): the Entry grids
      row's KEY2 is "back" on the go-ahead code and on the backup-passphrase entry of "Check a backup", and stays "-"
      on the read-back and BIP39-passphrase entries.

    Otherwise: a letter wheel (Up/Down cycles a character), or KEY1 always means Back.

    (b) Recommended: the backup passphrase is typed on the Pi ("Check a backup", pi-firmware.md:121) as the first four
    letters of each word, or a whole three-letter word, through a new core call
    `TypedBackupPassphrase::from_first_four(words: &[&str])`. That is the read-back rule and BIP39's four-letter
    uniqueness: at most 32 letters instead of about 44. No word list leaves core; anything else is refused before any
    scrypt run.

    Otherwise: whole words through the existing `from_words` (no core change); a public prefix helper with completion;
    or a direct `bip39` edge in pi/app.

    (c) Recommended: the Pi takes BIP39 passphrases of printable ASCII (0x20-0x7E), up to 100 characters. A wallet whose
    passphrase uses other characters gets no watch-only export from the Pi; its user builds the watch-only wallet in
    their coordinator after restoring. pi-firmware.md:93 says so.

    Otherwise: a larger character set on extra grid pages (accented Latin, chosen now), or a longer limit.

33. **Flow details the docs leave open (pi-firmware.md:80-96; seal-watchonly-braille.md:108-164, :209, :278;
    lessons.md:31-36).**
    Recommended:
    - (a) With a snapshot loaded, Check now shows "Snapshot No. 4, dated 2026-03-01, 7 entries. Use it for this check?"
      before every snapshot reveal. Yes reveals; No stays in the check and opens the seal card with the same nonce.
    - (b) The seal card is three pages, then an actions page: the 8×8 image with the Seal ID; the Seal ID large, with
      its braille; the check QR; then Enter go-ahead code, Match found, Cannot check.
    - (c) "Add fresh entropy" and "Start again" restart with the destroyed session's length and mode. While a `Wiped` is
      kept (Q26), every new session comes from it, whether started from those buttons or from Home.
    - (d) Steps 10-15 run in order. Steps 11-14 each open with Do it / Skip. The backup passphrase is generated at most
      once.
    - (e) The watch-only export is the account QR, then one descriptor QR holding both descriptors on two lines, as
      seal-watchonly-braille.md:209 says (301 bytes: version 11 at 3 px per module).
    - (f) Finish is terminal: checklist, session wiped, black frame, "Safe to power off" (pi-firmware.md:5 "runs one
      ceremony"). A loaded snapshot stays until power-off.
    - (g) When a stick holds several `.kcr` or `.age` files, a picker lists them. Only names of up to 64 characters
      from `[A-Za-z0-9._-]` ending in `.age` or `.kcr` (any case) are listed.
    - (h) A wrong backup-confirm pick shows the 8 words again and asks the same questions. The passphrase is never
      regenerated, since that would void the paper copy.
    - (i) About shows: version, root filesystem hash prefix, registry key state, licence, and admin@keepcrypt.com.
    - (j) A "TEST REGISTRY" strip on every screen when the build carries the test key, and "SIMULATOR" in the
      simulator.
    - (k) Blocking calls run behind a wait screen: the known-answer tests in a new session, the three scrypt runs and
      snapshot verification. No threads in M3; todo.md:2313's worker thread is decided in M4, after measuring.
    - (l) On the code path the device cannot know the checker's snapshot date, so the result reads "No collision for
      seal <Seal ID>, as of the date your checker showed." (seal-watchonly-braille.md:150 gains this line). "Check a
      backup" shows its lookup count with "as of <snapshot date>".
    - (m) Read-back: no suggestions while typing; after 3 or 4 letters the device completes the word from the seed and
      compares; a match shows the whole word. That is seal-watchonly-braille.md:278's "completes each word", so no doc
      edit.

    Otherwise: choose any item differently. (a) stays before every snapshot reveal in every option.

34. **Doc edits, applied alone in commit 2 (CLAUDE.md in its own commits), and owner item 13.**
    Recommended:
    - build-plan.md: :76 the Pi crates (Q28); :91 and :202-204 name `game_random` (Q27); :153 `restart(&self, ..)`
      (Q26); the sketch adds `TypedBackupPassphrase::from_first_four` (Q32).
    - pi-firmware.md:
      - :62 the simulator (Q28); :68 "Snake (Tetris later)", :69 the ceremony loop forwards presses and games get no
        sink, :70 the QR crate (Q27, Q28);
      - :75 and :82 any failure, at boot or later, halts until a power cycle (Q25);
      - :80 "fifteen screens in a fixed order: the typestate orders steps 1-8, core's read-back gate holds back the
        five exports until step 9 completes, and the firmware runs steps 10-15 in order, each optional one with a
        Skip";
      - :85 Snake only; :88 the seal-card pages and the date confirmation (Q33); :89 Press on the last insert starts
        the read-back (Q32); :93 printable ASCII BIP39 passphrases (Q32 (c));
      - :95 "type each value into verify.py only after its prompt appears" (todo.md:5321);
      - :100 the ceremony loop forwards key timing; :103 "Nothing derived from the pool is drawn by a game or the
        extras", since C and D are drawn by design (Q27);
      - :117 the backup write never replaces an existing file; :121 first four letters (Q32 (b));
      - new subsections for the buttons (Q32), protected screens and idle (Q29), and Finish and halts (Q25, Q33 (f)).
    - seal-watchonly-braille.md: :146 (Q25, Q26); :150 the code-path result (Q33 (l)); :200 M3 computes go-ahead codes
      in its tests, and the local test registry is M9's (Q30 (d)); :292 names `game_random`, Tetris later (Q27).
    - mobile-apps.md:142 names `game_random`.
    - design.md: :264 one process, with the games holding no path to the session (Q27 (b)); :285 the waiting-screen
      game lands with the Pi app (M3).
    - CLAUDE.md: rule 1 (CLAUDE.md:47) names `game_random` and its limits; Commands gain the simulator commands.
    - No edit needed: design.md:224 (the summary's fingerprint and address are what a restore is compared with);
      mobile-apps.md:166 (holds once the Pi has the privacy gate); seal-watchonly-braille.md:209 and :278 (Q33 (e),
      (m)).
    - No computed number is added (lessons.md rule 1).
    - Owner item 13 (the seed-pipeline figure, todo.md:453-455) stays open, outside M3: send the source file and I
      redraw it in commit 2; otherwise M7's docs pass draws it from a committed script.

    Otherwise: name the edits to leave out; the code then follows the doc text as it stands, except where a
    question above was answered the other way. For item 13, a hand-written SVG now.

### Raised by stage C's review during M3 (KEY2 "back", answered 2026-10-13)
An owner decision taken during M3, after the Q25-Q34 answers. It amends Q32 (a)'s key map (the Entry grids row), and
stage C's reviewers (commits 11-12) found the problem it fixes.
- [x] **No way back from the go-ahead code or the backup-passphrase entry.** Once a check is on `code-entry` (or on
      `code-wrong`, which returns to `code-entry`), no key reaches `check-actions` or the seal card. If the checker
      says Stop, or the user picks "Enter go-ahead code" before scanning, the only ways out are the 10-minute idle
      wipe or a power cycle. The idle wipe drops the `Checking` session without a `Wiped`, so no collision report is
      shown and, unless a kept `Wiped` already asks for 99 rolls (Q26), the next session needs 50, not 99.
      `backup-check-entry` has the same shape: its only exits are 8 entries or the idle wipe. Answered 2026-10-13, in
      the owner's words: "yes to KEY2 back". Decided:
      - on `code-entry`, KEY2 is "back": it returns to `check-actions` with the same `Checking` session and the same
        nonce, and the typed code is cleared;
      - on `backup-check-entry`, KEY2 is "back": it returns Home and drops the backup that was read (the file stays on
        the stick);
      - `readback-entry` and `bip39-entry` keep KEY2 "-".
      Applied in commit 18, with no code, as commit 2 did for Q34: pi-firmware.md's Buttons table and its Entry grids
      note, step 7's seal card and "Check a backup" (under "Restoring later"); Q32 (a)'s amendment, the screen
      inventory, and group 15 with its Verification line in this plan. seal-watchonly-braille.md and mobile-apps.md
      name no key of these screens, so neither changes. The code is commit 19 (group 15).

      Proof (commit 18): `git diff --name-only` lists only `docs/pi-firmware.md` and `tasks/todo.md`, and
      pi-firmware.md keeps its 188 lines; `vectorgen.py --selftest` (13 checks) and `verify.py selftest` (8 groups)
      pass on Python 3.12 and 3.9; `banned-api-check.sh` is clean (199 files) and `--selftest` passes 427/427; canaries 61/61.

### Later
- [ ] Release signing: minisign or GPG, and who holds the key offline? (M7)
- [ ] Registry domain name (M9; until then M1 uses a placeholder constant in the check-QR URL)

### Notes for later milestones
- The release symbol check expects libc `getrandom` and no `arc4random`. That fits Linux (Pi, Android). On iOS the
  `getrandom` crate calls `CCRandomGenerateBytes`, so M6 or M7 needs its own list of expected symbols.
- UniFFI converts Rust panics into Kotlin and Swift errors that app code could catch and then carry on. M5 must make
  any core panic wipe the session.
- Games (owner item 12 (b), 2026-10-10): M3 builds core's game-randomness call in `core/src/source`, a free function
  that fills a buffer from its own `getrandom` call and never touches the pool. The Pi games are its first user; M5
  and M6 reach it through the FFI. Its name then goes into build-plan.md's sketch (which today says "the games'
  call"), and into CLAUDE.md rule 1, pi-firmware.md, mobile-apps.md and seal-watchonly-braille.md, which call it
  "core's separate game-randomness call". Done in M3: core has `game_random` (17e4814), and all of them name it
  (c306bc2, and 28a0c5d for CLAUDE.md rule 1).
- 99 rolls after a collision (owner item 5, 2026-10-10): after a Stop or a Cannot check, the M3, M5 and M6 shells
  offer only `Wiped::restart`, never `Session::new`, so a restart after a collision keeps 99 rolls.
- M7 audit note (owner item 6, 2026-10-10): the accepted library residuals, which core cannot wipe:
  - rust-bitcoin's, secp256k1's and bip39's stack copies (the parent key in `derive_priv`, the HMAC state and output
    in `ckd_priv` and `new_master`, the tweak temporaries, the moved-from S of `to_seed_normalized`);
  - unicode-normalization 0.1.25's pending-character buffer, left unwiped on the stack by both NFKD passes and, for
    long decompositions, freed unwiped from the heap;
  - about six freed heap copies of the xpub while the export is built (public-key data);
  - hmac 0.13's padded key block (the seal's key S, the header MAC's key, scrypt's PBKDF2 steps);
  - HKDF's copies of the pseudorandom key derived from the file key;
  - scrypt 0.12's working buffers (Q1 (iii)), upstream issue
    https://github.com/RustCrypto/password-hashes/issues/938;
  - Poly1305's r and s are now wiped on drop (b4871b9), except the backends' stack temporaries: the soft backend's in
    `State::new` and `finalize`, and, on x86_64-linux-android, the AVX2 backend's.

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
     (`pi/app/src/games.rs`, `pi/app/src/games/`). (Changed 2026-10-10 in 73abaea, owner item 12 (b): the Pi games
     exemption is gone, so only `core/src/source.rs` and `core/src/source/` may name getrandom.)
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
  that returns game bytes from a separate getrandom call and never touches the pool. (Answered 2026-10-10, owner
  item 12 (b): the Pi and phone games all take their bytes from core's game-randomness call in `core/src/source`,
  built in M3; 73abaea removed the Pi games' Rule1 exemption.)

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
  - the phone games' byte source (M5/M6; this file, "Inputs from M0"). Changed 2026-10-10 (owner item 12 (b)):
    core's game-randomness call serves the Pi and phone games, is built in M3, and is reached through the FFI in
    M5/M6;
  - the "Verify another device" API (M5/M6);
  - UniFFI;
  - the birthday-collision job (M7);
  - real release binaries. The scan covers the core rlib and a release probe now; M3-M6 add their own binaries;
  - registry key rotation (M9).

**0. Before code**
- [x] Record the owner's answers to Q1-Q12 under "Needed before M1". Apply the approved doc edits (Q10) in their own
      reviewed commit (CLAUDE.md: docs and code must agree). Proof: the diff.
- [x] Branch protection (Q12), an owner action before the first M1 merge: a ruleset on `main` for `Entropy/**` that
      requires a PR and the Entropy CI jobs; approvals 0 while one account opens and merges every PR. Proof:
      `gh api repos/bitwilll/keepcrypt/rulesets` output under Review. Until the ruleset exists, this plan says
      "CI jobs", not "required checks".
      Done 2026-10-10 after the owner's explicit yes (owner item 1): ruleset 24833307 on `refs/heads/main`, active,
      no bypass actors, a PR with 0 approvals and the 14 Entropy check runs required. A ruleset cannot limit its
      checks to `Entropy/**` (Q12), so it covers every PR to `main`, and the changes job skips the other jobs on a
      PR that does not touch `Entropy/`. Proof: `gh api repos/bitwilll/keepcrypt/rulesets/24833307` under Review,
      "M1: the owner's answers applied". From here the 14 check runs are required checks.

**1. Workspace and supply chain**
- [x] Profiles and features (Q11):
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
- [x] Each new crate lands in the commit of the module that first uses it, with its cargo-vet entry, exactly as in the
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
- [x] Layout (build-plan.md "Modules"; CLAUDE.md rule 1; this file, "Inputs from M0"):
      - `lib.rs` holds `#![forbid(unsafe_code)]`, the modules and re-exports only;
      - modules: `error.rs`, `secret.rs`, `kat.rs`, `source.rs` + `source/{os,stub}.rs`, `health.rs`, `pool.rs`,
        `dice.rs`, `seed.rs`, `braille.rs`, `ur.rs`, `descriptor.rs`, `seal/`, `backup/`, `session/`;
      - integration tests in `core/tests/`, helpers in `core/tests/common/mod.rs` (plain `mod common;`);
      - only `source/os.rs` names the OS RNG crate; everything else calls `source::fill_os`.
      Proof: banned-API gate clean.
- [x] `error.rs` (thiserror 2; build-plan.md invariants; CLAUDE.md rules 3, 5):
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
- [x] `secret.rs` (CLAUDE.md rule 5; build-plan.md "secret"):
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
- [x] Session skeleton:
      - `Session<S> { inner: Box<Inner>, state: PhantomData<S> }`;
      - a sealed `State` trait over uninhabited `Collecting`, `Committed`, `Rolling`, `Sealed`, `Checking`, `Ready`;
      - one `Inner` holds every secret at fixed capacity, so nothing reallocates and there is no `Option` to unwrap;
      - `Inner`'s `Drop` zeroizes;
      - `Session::new` runs the KATs.
      Group 9 adds the transitions.
- [x] `kat.rs` (build-plan.md "kat" and test matrix row 1; design.md "Known-answer tests"):
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
- [x] `vectors/kat.json` and verify.py check 5:
      - contents: NIST FIPS 180-4 SHA examples, RFC 4231 case 2, RFC 8032 TEST 1 (Q3);
      - check 5 recomputes the SHA and HMAC entries with hashlib and hmac;
      - check 5 also reads the committed file: each section's entry names and every entry's keys are pinned, the SHA
        and HMAC values are recomputed from the file's own inputs, and the RFC 8032 entry must match a pinned
        SHA-256 of its bytes, taken from the RFC, until check 10 verifies it (review fix after commit 5);
      - one SOURCES.md row per standard.
      Proof: selftest passes on 3.12 and on `/usr/bin/python3` 3.9.
- [x] `source/stub.rs` (`#![cfg(feature = "test-sources")]`; CLAUDE.md rule 10):
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
- [x] Vectors first (lessons.md; Q6a, Q7). `verify.py --write-keepcrypt-vectors` writes `vectors/keepcrypt.json`:
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
- [x] `source.rs` (build-plan.md "source", "Credit policy"; design.md "Mixing and conditioning", the getrandom bullet;
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
- [x] `health.rs` (SP 800-90B 4.3, 4.4.1, 4.4.2; alpha 2^-20, H = 4; design.md "Test continuously"; Q7):
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
- [x] `pool.rs` (CLAUDE.md rule 4; build-plan.md "pool"; Q6a):
      - `new()` absorbs the 11 bytes `KCE/v1/pool` once;
      - each record is id u16 BE, `u64::try_from(len)` BE, then the data; empty data writes no record;
      - `finish` returns D = SHA-512(...)[0..32] and zeroizes the digest;
      - a compile-time check confirms the sha2 hashers are `ZeroizeOnDrop`.
      Proof:
      - empty-pool and record vectors; records ("ab", "c") and ("a", "bc") give different D;
      - pipe width (CLAUDE.md rule 2): each of the 512 single-bit flips of the 64-byte OS record (base bytes from
        SHA-256 counter mode) changes D.
- [x] KAT groups:
      - Pool: one record vector;
      - Health: a stuck stream fails RCT and an alternating stream fails APT, each at its pinned index; a clean stream
        passes.
      Proof: the constants match keepcrypt.json.

**4. dice, seed**
- [x] `dice.rs` (build-plan.md "dice"; CLAUDE.md "Dice quota"; this file, "Inputs from M0": R is exactly ASCII 1-6):
      - a fixed `[u8; 256]` buffer plus a length, with no Vec, so growth never leaves copies;
      - faces 1-6 map to `b'1'..=b'6'` by `match`; 0 and 7+ are `InvalidRoll`; roll 257 is `TooManyRolls`;
      - undo zeroes the removed byte and does nothing when no rolls are entered;
      - count and millibits (count x 2585; 37 rolls show "95.6 bits", pi-firmware.md step 6);
      - minimum rolls: 50 for 12 words, 99 for 24, 99 after a collision. Review fix after commit 10: 99 rolls give
        255.9 bits (99 x 2.585), not 256, and the code now says so; design.md "Recommended architecture" still says
        "256 with 99 rolls". Whether the 24-word minimum should become 100 rolls (258.5 bits) is a
        question for the owner, a doc change (CLAUDE.md "Dice quota", design.md); until answered, 99 stands.
        Answered 2026-10-10 (owner item 4): 99 stays, and design.md now says "about 256 (255.9)" (012c8db); the
        sentence under the seed-pipeline figure says its "99 give 256" rounds up (6ba465c).
      Proof: unit tests, including that R only ever holds `b'1'..=b'6'`.
- [x] `seed.rs` (CLAUDE.md "Commitment", "Seed"; design.md "From entropy to a BIP39 seed phrase"; build-plan.md
      invariants):
      - C, mixed E and dice-only E exactly as in CLAUDE.md;
      - 12 words from E[..16], 24 from E[..32], via bip39 English, converted at once to `SecretMnemonic`;
      - S = `to_seed_normalized("")`, wrapped in `Zeroizing`;
      - wallet summary: the master fingerprint and the m/84'/0'/0'/0/0 P2WPKH mainnet address. Xprivs stay inside
        one function and are erased; the secp256k1 context is not randomized.
      - Review fix after commit 10: a single 5-step `derive_priv` left m/84', m/84'/0', the account key m/84'/0'/0'
        and m/84'/0'/0'/0 in rust-bitcoin's frame, never erased. Core now derives one level at a time and erases
        every Xpriv it holds (master, each intermediate, leaf) on every path. Residual risk, for the owner's review
        (accepted 2026-10-10 as an M7 audit note, owner item 6; compare Q1 (iii) for scrypt): copies core cannot
        reach stay on the stack, namely
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
- [x] KAT group Seed: C, mixed E, dice-only `123456`.

**5. braille**
- [x] Vectors first (this file, "Inputs from M0"; lessons.md; seal-watchonly-braille.md "Tests and cross-checks").
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
      not approved this change; it is Q15 (review fix after commit 15). Approved 2026-10-10 (owner item 3).
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
- [x] `braille.rs` (seal-watchonly-braille.md "Braille backup"; CLAUDE.md "Braille"):
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
- [x] Read-back compare (seal-watchonly-braille.md "Read-back from the metal"; pi-firmware.md step 9):
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
- [x] KAT group Braille: SHA-256 of the canonical table text, plus `2026`. Proof: one flipped dot, or two swapped
      words, makes the group fail (unit test, injected).
      As built, approved with Q15 on 2026-10-10: one flipped dot, or two letters' cells swapped, fails the Braille
      group. Two swapped words fail the Bip39Wordlist group, the source of braille's words.

**6. ur, descriptor, watch-only** (the seal's proof QR reuses `ur.rs`, so this group comes before the seal)
- [x] Vectors first. `verify.py --write-watchonly-vectors` writes `vectors/watchonly.json`, using:
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
- [x] `ur.rs` (Q2, Q6c; BCR-2020-005, -012):
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
- [x] `descriptor.rs` (build-plan.md "descriptor"; seal-watchonly-braille.md "Watch-only export"):
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
- [x] `crypto-account` and the export (BCR-2020-015, -007; Q2; seal-watchonly-braille.md "Watch-only export" rules):
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
      Residual risks found in review after commit 15, for the owner's review (accepted 2026-10-10 as an M7 audit
      note, owner item 6; compare group 4):
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
- [x] KAT group Bip84 (abandon: fingerprint, xpub, first address, receive checksum, UR). It catches a miscompiled
      secp256k1-sys on a target. The Seal group later reuses its PBKDF2.

**7. seal**
- [x] Vectors first. `verify.py --write-kcr-vectors` writes `vectors/kcr.json` (hex text), using a stdlib RFC 8032
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
- [x] `seal/crockford.rs` and seal derivation (seal-watchonly-braille.md "Seal derivation spec", "The seal image";
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
      - Residual risk, for the owner's review (accepted 2026-10-10 as an M7 audit note, owner item 6; compare group
        4): hmac 0.13's `new_from_slice`
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
- [x] Check request and go-ahead (seal-watchonly-braille.md "The seal card", "Online lookup privacy", "Go-ahead code";
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
- [x] `seal/merkle.rs` (CLAUDE.md "Bucket proof"; seal-watchonly-braille.md "Snapshot format"; Q6b):
      - leaf and node exactly as in CLAUDE.md, with the prefix written as a 24-bit big-endian bucket index;
      - the root comes from one streaming pass with at most 21 stacked hashes;
      - paths run leaf level first, and direction bit j = (i >> j) & 1.
      Proof: empty leaves 0, 0x2b810 and 0xFFFFF; a node vector; the empty-snapshot root; the left-aligned reading
      (`2b 81 00`) is shown to give a different leaf and is not used.
- [x] `seal/snapshot.rs` (build-plan.md `verify_snapshot` and CI rule "Only authentic snapshots are used"; Q6b):
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
- [x] `seal/proof.rs` (seal-watchonly-braille.md "Go-ahead QR"; Q2, Q6c):
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
- [x] `seal/registry_key.rs` and registration (seal-watchonly-braille.md "Registry service spec", "Registering a new
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
- [x] KAT groups:
      - Seal: the vector-1 code, T and Seal ID (review fix after commit 18: from the abandon words through
        `seed_from_mnemonic_into`, with S compared to `ABANDON_SEED`, and the Seal ID's braille caption);
      - GoAhead: `CF94-BCAJ`; a wrong n fails;
      - Ed25519: RFC 8032 TEST 1 is accepted; one flipped bit is rejected;
      - Merkle: a leaf, a node and the vector-1 path. Never a full root.

**8. backup (age v1, scrypt only)**
- [x] Vectors first:
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
        and the CI `age-interop` job (commit 27) runs it against Ubuntu 1.1.1 in both directions. Not approved
        by the owner: it is an open item under "Raised by the review of commits 19-21", and the 1.1.1 proofs stay
        unticked until it is answered. Approved 2026-10-10 (owner item 7).
      - Q1 (i) says "a 24-word backup is 1,718 bytes armored"; that was a planning estimate. The computed
        maximum is 1,726 armored bytes for 24 words (a 1,042-byte plaintext; backup.json `limits`, regenerated
        by check 11); 1,718 is the armor of a 1,034- to 1,036-byte plaintext. Both are far inside the 8 KiB cap,
        and the owner's Q1 text stays as written (review fix after commit 21).
      - verify.py's age is written from the C2SP age spec (`age.md`, downloaded twice on 2026-10-10 with a generic
        User-Agent, recorded in SOURCES.md "Spec values"); it rebuilds CCTV `scrypt` and `armor_scrypt` byte for
        byte and reaches all 26 CCTV outcomes.
- [x] `backup/armor.rs` (build-plan.md "Container"; C2SP age "ASCII armor"):
      - encode: 64-column padded base64, exact labels, LF line endings;
      - decode accepts only surrounding ASCII whitespace, LF or CRLF, full 64-character lines (except a last line of
        1-64), and canonical padding (base64ct). (Changed 2026-10-10 in d8b5d25: whitespace only after END; the
        last bullet of this item.)
      Proof: armoring CCTV `scrypt` gives `armor_scrypt` exactly; CRLF is accepted; these negatives all fail:
      lowercase label, a 63- or 65-character line, an empty last line, bad or non-canonical padding, an inner space,
      text after END, no END, a BOM.
      Review fixes after commit 21 (the readers now refuse whitespace the age CLI refuses):
      - verify.py read an END line ended by a lone CR at the end of the input as `END\r` and refused it; core and
        age 1.3.2 accept it. verify.py now strips that CR too, and backup.json gains `abandon-12-end-cr`.
      - (The rule before BEGIN changed on 2026-10-10; see the next bullet.) Core and verify.py accepted any amount of
        space, tab, CR and LF before BEGIN, on BEGIN's own line too, and
        after END up to the 8 KiB cap, so `verify_backup` and `decrypt_backup` could pass a file the age CLI cannot
        open (build-plan.md: the file opens "with the open-source age tool, without KeepCrypt"). age 1.3.2 refuses
        a space or tab before BEGIN on its line ("invalid first line"), more than 1,024 bytes before BEGIN and
        1,024 or more after END ("too much trailing whitespace"); it accepts form feed and vertical tab there,
        which core keeps refusing (stricter is safe). Both readers now allow at most 1,024 bytes of whitespace
        before BEGIN, in whole lines (empty or ending in LF), and fewer than 1,024 after the END line. backup.json:
        `abandon-12-8192-bytes` (7,198 trailing spaces, which age refuses) is gone; `abandon-12-leading-1024` and
        `abandon-12-trailing-1023` are accepted at the edges; `armor-space-before-begin`,
        `armor-tab-after-blank-line`, `armor-leading-1025`, `armor-trailing-1024` and `armor-8192-bytes` give
        `Backup(Armor)` before any scrypt work (42 refused files). No accepted armor can now reach 8,192 bytes
        (a 4 KiB chunk armors to 5,862 bytes with LF line ends and 5,954 with CRLF, plus at most 2,047 of
        whitespace), so `armor-8192-bytes` shows the size cap lets 8,192 bytes through to the armor rules, and
        `too-large` (8,193) still gives `TooLarge`. age 1.3.2 decrypts every accepted variant and refuses all five
        new cases; Ubuntu's 1.1.1 is not checked here.
      - Changed 2026-10-10 (d8b5d25), after CI's age-interop job failed on 4733e4a: age 1.1.1's CLI, the one the CI
        job runs, reads armor only when BEGIN is at byte 0 (v1.1.1 cmd/age/age.go: `rr.Peek(len(armor.Header))`).
        age 1.3.0 and later skip up to 1,024 bytes of leading whitespace (v1.3.1 cmd/age/age.go lines 495-497);
        1.2.0 and 1.2.1 still read armor only at byte 0. The readers had copied the 1.3 rule, so 1.1.1 refused
        `abandon-12-whitespace` and `abandon-12-leading-1024`. Both readers now refuse any whitespace before BEGIN,
        which C2SP age allows; after END the rule above stands (fewer than 1,024 bytes). backup.json:
        `abandon-12-leading-1024` is gone; `abandon-12-whitespace` became `abandon-12-crlf-trailing-whitespace`
        (CRLF armor, then " \r\n\t\n"); `armor-newline-before-begin` (one LF), `armor-whitespace-lines-around` (the
        old whitespace file) and `armor-leading-1024` (in place of `armor-leading-1025`) are refused with
        `Backup(Armor)`. That makes 11 accepted and 44 refused files. An accepted armor now reaches at most
        5,954 + 1,023 bytes (a 4 KiB chunk armors to 5,862 bytes with LF line ends and 5,954 with CRLF), still under
        8,192. Check 11 also requires every accepted file to start with the BEGIN line or `age-encryption.org/v1`
        and LF. age 1.3.2 decrypts all 11 and accepts three of the refused armor cases (printed as notes; stricter
        is safe). In CI on 34beea2, age 1.1.1 decrypts all 11 and refuses all 17 armor cases (run 38041799043).
- [x] `backup/age.rs` (C2SP age v1; build-plan.md "Recipient: scrypt only"; Q1 reader policy):
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
        only what the reader reads; no single flipped bit of a binary backup is accepted (review fix after commit
        21: the test flipped one bit per byte, 683 of abandon-12-binary's 5,464 single-bit flips; it now tries all
        5,464, about 6 s at work factor 10, and the reader refuses every one).
      - chacha20poly1305 and base64ct are built without `alloc` (table A lists it): core uses the in-out AEAD calls
        and slice encoding, which need no allocation. The lock entries are the same either way.
      - Residual risk, for the owner's review (accepted 2026-10-10 as an M7 audit note, owner item 6; Q1 (iii)
        accepted scrypt's buffers): HKDF's
        extract step keeps copies of the pseudorandom key, derived from the file key, in its own frames (the copy
        it returns is wiped), and the header MAC's hmac leaves its padded key block, as recorded in group 7.
        Review fix after commit 21, two more for the same decision:
        - Poly1305's one-time key. chacha20poly1305 0.11.0's `zeroize` feature turns on only `chacha20/zeroize`
          and wipes the 32-byte MAC key it derives, but poly1305 0.9.1 resolves with no features (`cargo
          metadata`: `poly1305 0.9.1 []`, declared `zeroize`), so `impl Drop for Poly1305` skips
          `zeroize_flat_type` and r and s stay in the dropped cipher's state, once for the stanza body (under
          the wrap key) and once for the payload (under the payload key). They are the first ChaCha20 keystream
          block, so they reveal neither the ChaCha20 key, nor the file key, nor the plaintext. Wiping them needs
          poly1305 as a direct dependency with `zeroize`, a new edge (owner approval and a vet entry), so
          nothing is changed until the owner decides. Table A's resolved features are as written, so this is no
          dependency deviation. Changed 2026-10-10 (owner item 6): b4871b9 adds poly1305 0.9.1 as a direct edge
          with `default-features = false, features = ["zeroize"]`, named in build-plan.md by 0ac7394. Cargo.lock
          gains two lines and no package. `Drop for Poly1305` now wipes r and s, except the backends' stack
          temporaries: the soft backend's in `State::new` and `finalize`, and, on x86_64-linux-android, the AVX2
          backend's. Those stay, in the M7 audit note. poly1305 compiles its AVX2 backend for x86 and x86_64 and
          picks it at run time when the CPU has AVX2 (src/backend.rs, backend/autodetect.rs); backend/avx2.rs has
          no zeroize. canaries.sh pins the feature on each target (7c46d93).
        - scrypt's PBKDF2 steps key hmac with the backup passphrase (`pbkdf2_hmac` calls `new_from_slice`), so
          the group 7 hmac residual applies there too, to a passphrase-derived block.
- [x] `backup/passphrase.rs` (build-plan.md "Passphrase"; pi-firmware.md USB steps 1-2; mobile-apps.md "Encrypted
      backup only"; Q6e):
      - 11 fresh OS bytes, cut into 8 indices of 11 bits;
      - the age passphrase is the 8 lowercase words joined by single spaces;
      - `TypedBackupPassphrase::from_words` accepts exactly 8 words, each exactly as in the list; only
        `decrypt_backup` takes one;
      - the core also draws the 2-of-4 confirm challenge, without modulo bias.
      Proof: layout vectors (zeros give abandon x 8; ff x 11 gives zoo x 8); each of the 88 single-bit flips changes
      exactly one word; the challenge equals its stub-stream value; a trybuild fixture shows typed words cannot reach
      `encrypt_backup` or `verify_backup` (group 10).
- [x] `backup/plaintext.rs` (build-plan.md "Plaintext inside the file"; seal-watchonly-braille.md "Inside the
      encrypted backup"; Q6e):
      - writes the exact v1 bytes;
      - the parser checks the BIP39 checksum and the fingerprint, then requires byte equality on re-serialization;
      - `keepcrypt-backup/v2` gives `UnsupportedVersion`;
      - the BIP39 passphrase has no way in.
      Proof: the abandon x 11 + about and zoo x 23 + vote vectors; CRLF, a BOM, a missing final LF, uppercase,
      18 words, a bad checksum, mismatched braille and a wrong fingerprint all fail.
- [x] Backup API (Q5; build-plan.md "Encrypted backup format" rules):
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
      - the age 1.1.1 files decrypt (as approved 2026-10-10, owner item 7: the age CLI files written with 1.3.2,
        `backup::tests::the_age_cli_files_decrypt`).
- [x] "Check a backup" (pi-firmware.md "Encrypted backup to a USB stick"; mobile-apps.md "Checking a backup";
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
      Proof: the age 1.1.1 files (as approved 2026-10-10, owner item 7: the age CLI files written with 1.3.2) and a
      fresh core file give the vector fingerprint and seal; `reveal_words()` equals
      the vector words; a wrong typed passphrase gives `WrongPassphrase`; trybuild and no-secret-text coverage
      (group 10).
- [x] KAT group Age, using CCTV `scrypt`, `armor_scrypt` and `scrypt_work_factor_23` through `include_bytes!` (pinned
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
        requires byte equality. `CreatedBy::new(BackupApp, major, minor, patch)` is public metadata.
        Review fix after commit 21: "every failure but `UnsupportedVersion` is `Backup(Plaintext)`" held by
        relabelling. The reader mapped every error of `seed_from_mnemonic_into` and `wallet_summary` to
        `Backup(Plaintext)`, so a fault in core's own derivation (BIP32 at odds of 2^-128, a constant path)
        came back from `verify_backup(&self)` as a retryable malformed file, and age's `Internal(Length)` paths
        passed through anyway. Now the BIP39 checksum, the one rule there a file can break, is checked on its
        own (`seed::checksum_is_valid`, split out of `seed_from_mnemonic_into`) and gives `Backup(Plaintext)`;
        the derivation's errors stay `Internal`. A scratch probe that made `wallet_summary` fail gave
        `Backup(Plaintext)` from `decrypt_backup` and `verify` before, and `Internal(KeyDerivation)` after. So
        for every input the file decides, `verify_backup` returns only the four errors build-plan.md lists;
        `Internal` comes only from that derivation or from age's fixed-size library calls (scrypt's 32-byte
        output, HKDF's 32-byte expand, an HMAC key), which no input reaches. Hand-off to commit 22 (Q13 (b)):
        `verify_backup(&self)` cannot wipe, so group 9's error-list test settles what such an `Internal` does:
        either the test pins the four errors for every input and names these unreachable paths, or
        `verify_backup` gets its own narrower error type, as Q13 (b) allows.
      - API: `Session<Ready>::generate_backup_passphrase(self)`, `encrypt_backup(self, &CreatedBy)` and
        `verify_backup(&self, file)`, with the passphrase stored in `Inner` and the fingerprint in a new `Inner`
        field that `finish` fills (group 9). `encrypt_backup` reads the file key, salt, nonce and file name from
        the OS source in that order (52 bytes, proven with an exact stub). `BackupFile` has `name()` and
        `bytes()`; `CheckedBackup` has `fingerprint()`, `seal()`, `reveal_words()` and `reveal_braille()` (the
        insert views of the verified words). Hand-off to commit 22: nothing reaches `Session<Ready>` yet
        (`skip_check` and `reveal` are group 9), so these calls are tested on a test-only `ready_for_test`
        constructor, and the read-back gate in front of `generate_backup_passphrase` and `encrypt_backup`
        (`ReadbackIncomplete`) lands with the session transitions.
      - Review fixes after commit 21 (tests that left part of a proof unchecked; each confirmed with a mutant in a
        scratch copy, which passed every test before and fails after):
        - The file key. The 52-byte stub proved where the salt, nonce and name came from, not the file key: a
          writer wrapping a constant, the salt or the nonce as the file key passed all 172 test-sources tests and
          `age-interop.py --core`, and its backups opened without the passphrase. The stub test now requires the
          file to equal, byte for byte, the armored writer output from drawn[0..16] as the key, drawn[16..32] as
          the salt and drawn[32..48] as the nonce at work factor 18; the real-OS two-backups test opens both file
          keys (a test-only `age::file_key_of`) and requires them to differ and neither to equal its salt or
          nonce. All three mutants now fail both tests.
        - The read-back's word check. Both `ReadbackMismatch` cases also had a wrong fingerprint; a case with the
          right fingerprint and other words now isolates the word comparison.
        - "runs the Age KAT first". Files the reader refuses (not age, empty, a wrong passphrase) now give
          `Kat(Age)` from the fault twin, so moving the group after `age::decrypt` fails.
        - The seal. The age CLI's two abandon-12 files and the fresh work-factor-18 abandon-12 backup now give
          seal.json's vector 1 (CLAUDE.md's T `2b8103c8...` and Seal ID `5E0G7J6X`) through
          `CheckedBackup::seal()`; the round trip compared the seal with `seal_from_mnemonic` of the same words,
          and the age CLI files checked none.
      - Interop: `scripts/age-interop.py --core` also runs core in both directions through the ignored unit test
        `backup::tests::age_interop_files`: core's `decrypt_backup` reads files age wrote under fresh passphrases,
        and age decrypts core's fresh work-factor-18 backups to backup.json's plaintexts; a wrong passphrase fails
        in age. Run locally with age 1.3.2; the CI job (commit 27) runs it with Ubuntu's 1.1.1.
        Review fix after commit 21: in every mode the script also gives the age CLI every backup.json age file the
        readers accept (the written files and the reader-only armor variants) and fails unless each decrypts to
        its plaintext, so a reader that accepts a file age refuses no longer goes unnoticed; against commit 21's
        backup.json it fails on `abandon-12-8192-bytes` ("the readers accept it, age exits 1"). The armor cases
        the readers refuse go to age too; one that age accepts is printed as a note, not a failure (stricter is
        safe). With age 1.3.2: "age decrypted all 12 backup.json age files the readers accept, and also refused
        15 of the 15 armor cases they refuse". (Changed 2026-10-10 with d8b5d25: "all 11 ... and also refused 14 of
        the 17", with the three 1.3.2 accepts printed as notes.)

**9. session** (build-plan.md "Public API" as refined by Q5; CLAUDE.md rule 6; seal-watchonly-braille.md "Ceremony
order", "Go-ahead before reveal")
- [x] Transitions:
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
- [x] Collecting and commit (build-plan.md "Credit policy"; pi-firmware.md "Dice-only mode skips steps 4, 5 and 14"):
      - `add_hw_samples` works on the Pi in Mixed mode only (else `NotInThisMode`): health test first, then one hwrng
        record of the post-startup bytes;
      - `credited_bits` stays 0 until the first post-startup window completes, then jumps to 2,048 (512 required);
        `hw_bytes_tested` and `HW_BYTES_NEEDED` feed the pi-firmware.md step 4 progress bar (Q7, Q10);
      - `add_extra` is never credited and cannot change the credit;
      - `commit` checks the quota, reads 64 OS bytes and absorbs them last, then derives D and C;
      - dice-only mode: no pool and no OS read; `commitment()` and `reveal_device_leg()` give None; `add_extra` does
        nothing.
- [x] Rolling, Sealed and Checking:
      - `finish` below the minimum gives `TooFewRolls`. Otherwise it derives E, the mnemonic, S, the seal, the
        fingerprint and the first address once, then zeroizes R;
      - `skip_check` exists only on Sealed;
      - `reveal`:
        - a malformed or wrong code gives `Retry` (same n, no wipe);
        - a snapshot or proof holding T[0..16] gives `Collision`, with a report and the 99-roll flag;
        - a proof for another bucket gives `Retry`;
        - freshness is the shell's warning, not a refusal: the core has no clock;
      - `discard(Collision)` keeps the report and the flag; `discard(CannotCheck)` keeps neither. (Changed
        2026-10-10, owner item 5, e87b296: `discard(CannotCheck)` keeps no report, but keeps the checking session's
        own 99-roll flag.)
- [x] `Wiped::restart` (seal-watchonly-braille.md "Add fresh entropy"; CLAUDE.md "Dice quota"):
      - `Wiped` holds no secret;
      - restart re-runs the KATs, starts a fresh pool, and does a fresh OS read at commit;
      - the minimum is 99 rolls for both lengths after a collision, and the normal minimum after CannotCheck
        (changed 2026-10-10, owner item 5: after CannotCheck, the checking session's own minimum, so 99 rolls stay
        after a collision until a check passes);
      - `Rejected` and `Wiped` get hand-written `Debug` that never touches their contents and prints no BIP39 word
        (group 10).
- [x] Ready and panics (Q5; CLAUDE.md rule 3):
      - `check_readback` records each matched position, and a later mismatch clears it. Read-back errors never wipe;
      - the exports return `ReadbackIncomplete` until every position has matched;
      - core never panics on public input. A panic unwinds and drops `Box<Inner>`; `catch_unwind` stays banned;
      - note for M5: the FFI takes the session out of its slot before each call, so a panic leaves no session behind.
- As built at commit 22 (session.rs, session/inner.rs, session/wiped.rs):
  - The transitions are as in the table above. `Inner` holds every field at fixed capacity with no `Option` to
    unwrap: the tester, the pool, D and C, the dice, E, S, the words, the seal code and its public half (empty
    until `finish`), the fingerprint and first address, the nonce, the read-back flags and the stored backup
    passphrase; its `Zeroize` clears all of them and the white-box test fills and checks each.
    Review fix after commit 25: that `Zeroize` ends with the source's own buffers, where a stub counts the
    wipe on its probe, and `Drop` runs it; `Drop` used to bump the probe itself, so a `Drop` without the
    zeroize passed every test. One wipe on a probe now proves the drop zeroized every field. `HealthTester`
    also derives `ZeroizeOnDrop`.
  - `credited_bits()` and `required_bits()` return u64, not the sketch's u32 (the sketch says u64 since 62e2e5e,
    owner item 10): the screen gets the same sum
    `source::quota_met` compares, in its width, with nothing narrowed or defaulted (a u32 needs a saturating
    fallback, which the fail-closed ban refuses). On a phone in Mixed mode `credited_bits()` counts the OS
    read's 256-bit policy credit before `commit`, so `credited_bits() >= required_bits()` is exactly when
    `commit` can pass; dice-only mode reports 0 of 0.
  - `add_extra(&mut self)` cannot fail the session, so the pool's only failure (a length that does not fit a
    u64) is kept and `commit` returns it, wiping there. A unit test plants it.
  - `Wiped::collision_report(&self)` returns `Option<&CollisionReport>`, not the sketch's owned value (the sketch
    matches since 62e2e5e):
    `CollisionReport` has no `Clone`, and the `Wiped` keeps the one report. `Wiped` keeps the platform, so
    `restart(len, mode)` needs none. Under `test-sources`, `Wiped::restart_with_stub(len, mode, stub,
    kat_fault)` is the restart twin of `Session::new_with_stub`, so every `KatId` is injected at restart too.
  - `discard(CannotCheck)` keeps neither the report nor the flag, also in a session that itself started after a
    collision: that next restart uses the normal minimum, as seal-watchonly-braille.md "Add fresh entropy" says.
    Review fix after commit 25: no test pinned the second half (a mutant carrying the flag passed every test);
    `cannot_check_after_a_collision_restarts_at_the_normal_minimum` now does, at 12 words (99, then 50).
    Changed 2026-10-10 (owner item 5, e87b296): `discard(CannotCheck)` now keeps the checking session's own flag,
    so the restart after a collision keeps 99 rolls through every Cannot check until a check passes. The test is
    now `cannot_check_after_a_collision_keeps_99_rolls` (12 and 24 words, three Cannot checks in a row), and
    `the_99_roll_minimum_ends_at_a_passed_check` shows that a passed check ends it; `discard_and_restart` still
    pins a plain Cannot check at 50. seal-watchonly-braille.md "Add fresh entropy" says so (dc53b8f), including
    that any other wipe ends the minimum (open owner item 14).
  - Q13 (b), settled as its first option: `verify_backup(&self)` keeps `CoreError`, and a unit test
    (`the_two_calls_that_never_wipe_return_only_their_listed_errors`) pins that it returns only `Ok`,
    `NoBackupPassphrase`, `WrongPassphrase`, `ReadbackMismatch` and `Backup(_)` over every backup.json age file
    and refused file, every refused plaintext and another seed's plaintext under the session's own passphrase,
    and every truncation and a bit flip per byte of a backup under it; `check_readback` gives only
    `Braille(BadPosition)` and `Braille(MalformedReadback)` over every position and a range of typed input. The
    `Internal(_)` paths no input reaches are named in session.rs's module comment and `verify_backup`'s doc:
    core's derivation from checksum-checked words and age's fixed-size library calls.
  - `Rejected` and `Wiped` print `Rejected::Retry`, `Rejected::Collision` and `Wiped`, never their contents.
  - The panic policy is stated in session.rs; tests/panic_wipe.rs proves it (commit 25).
  - `ready_for_test` now leaves a session as `finish` does (seal and first address included, nothing read
    back), and the backup tests read every word back through `check_readback` before the gated calls, so the
    gate opens the honest way. Every dead-code expectation group 9 fulfils is gone.
  - Commit 22's message (cf1f797) gives core's line coverage as 97.29%. Re-run at that commit with the group
    12 command, cargo-llvm-cov 0.9.1 gives 97.37% (8,199 lines, 216 missed); review fix after commit 25.

**10. Cross-cutting tests**
- [x] `tests/typestate.rs` (trybuild; CLAUDE.md rule 6; build-plan.md "Sealed-state compile-fail tests"). Fixtures
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
      As built at commit 23: 23 fixtures (8 from group 2, 15 new), each with its pinned `.stderr`; the list by
      purpose is in tests/typestate.rs. No value is built: a fixture types a state as `Option<Session<_>>` set to
      None, so type checking alone decides. The errors are E0599 (a method absent from a state or from `Wiped`),
      E0277 (no `Debug`, `Display` or `Clone`), E0061 and E0308 (a passphrase handed to `encrypt_backup` or
      `verify_backup`, as an extra argument and in place of the real one), E0382 (`commit`, `reveal`), E0505
      (borrows) and E0423 or "cannot construct ... due to private fields" (struct literals: a literal with every
      field named is refused only by the privacy pass, which never runs after a type error, so each literal is
      written empty). The braille and read-back fixtures also cover `ReadbackMismatch`, `FaceVerdict` and `Dots`,
      and the seal fixture `CollisionReport`. trybuild builds the fixtures with the run's features, and every
      `.stderr` holds under default features, `test-registry` and `test-sources`. Two compiler suggestions name
      crate-private constructors (`SealPublic::empty`, `CheckNonce::from_bytes`); renaming either regenerates
      `no_struct_literals.stderr`. A mutant giving `Session<Sealed>` a `mnemonic()` fails three fixtures.
- [x] `tests/source_substitution.rs` (design.md "Prove the path" 1; build-plan.md test matrix):
      - fixed OS bytes, a counter-mode hwrng stream in 64-byte chunks and two extras give the keepcrypt.json D and C,
        on Pi and on Phone;
      - changing one byte of any source, changing a source id, or dropping an extras call changes D;
      - a changed but still healthy startup byte does not change D;
      - exactly 64 OS bytes are read;
      - dice-only E = SHA256(R) whatever the stubs, and a zero-byte stub still reaches Ready through Skip.
- [x] `tests/os_source.rs` (default features): two real Phone sessions give different commitments. It asserts
      inequality only and prints nothing.
- [x] `tests/error_injection.rs` (build-plan.md CI rule "Fail closed", test matrix "Error injection", "Repetition Count
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
- [x] `tests/check_flow.rs` (seal-watchonly-braille.md "Results"; public vectors only):
      - a 12-word dice-only session from the 50-roll string reaches Sealed with the kcr.json T;
      - the code reveals the expected words, and a typo keeps the session;
      - the collision snapshot and the collision proof both give `Collision`, whose report holds that seed's code;
      - restart refuses 50 rolls and accepts the 99-roll string;
      - a wrong-bucket proof gives `Retry`, and the right code still reveals;
      - the kcr.json stale proof gives `Stale` for its pinned today, as a phone shell sees it, and still reveals; the
        future-dated proof gives `Future`.
- [x] `tests/ceremony.rs`:
      - 12- and 24-word ceremonies reach Ready, and every insert reads back from its own faces;
      - exports fail before read-back;
      - `decrypt_backup` of the session's file gives a `CheckedBackup` whose fingerprint (empty passphrase), words
        and braille lines match the session, and whose `seal()` equals the session's seal;
      - after `watch_only(Some(TREZOR))`, the backup and the registration are unchanged and hold no passphrase.
- As built at commit 24 (core/Cargo.toml declares `required-features = ["test-sources"]` for source_substitution,
  error_injection and check_flow; os_source and ceremony run with default features, on the real OS source):
  - source_substitution: D is read through `reveal_device_leg` after a 50-roll ceremony reads every word back; C
    stands in for D where only a difference matters (C = SHA-256(tag || D)). Each change is one byte at both ends of
    every hwrng chunk, one byte of every extra and of the OS read; the 16 startup chunks leave C unchanged, and
    the 9 after them and every other source change it. Of those 9, one completed 512-sample window credits 8;
    the last is tested and absorbed but never credited (review fix after commit 25: this note and the test's
    message said 9 credited). A source id is changed to each of the other three extras.
    "Exactly 64" is proven both ways: 63 stub bytes fail `commit` with `Source(Os)`, and after 64 the stub is used
    up, so `start_check` fails. Dice-only reaches `Ready` through Skip on an empty stub, a stream and a failing
    stub alike, with keepcrypt.json's 12- and 24-word lists.
  - os_source: two phone commitments differ, and two checks of one dice-only seed share T but not the nonce.
  - error_injection: every case asserts the exact `Err` and one probe wipe: the OS failing at commit (Pi after 1,536
    clean bytes, phone), at `start_check`, in `generate_backup_passphrase`, and in `encrypt_backup` with nothing or
    only the file key left; short reads at each of those; every keepcrypt.json health case through
    `add_hw_samples` in 64-byte chunks (each failure at its pinned test, stage and sample; each pass tested,
    credited and committed as pinned); 1,535 bytes and 1 MiB of each extra give `QuotaUnmet`; hwrng input on a
    phone or in dice-only mode; faces 0, 7, 255 and a 257th roll; `finish` at 49, at 98 and at 98 after a collision
    for both lengths; the five exports before read-back and `encrypt_backup` before a passphrase; every `KatId` at
    `new` and at `restart_with_stub`. The free-function twins are swept against one exhaustive match, `runs(id)`,
    from group to entry points (kat.rs `groups` read the other way): `Kat(id)` where a function runs the group,
    else its own known answer. Every valid snapshot costs a full root pass (1.45 s), so the snapshot twin reads
    kcr.json's `truncated-body`, which passes the signature check and is refused for its length; tests/kcr.rs
    verifies the valid snapshots. Mutant check: a commit that swallows an OS error fails two of these tests.
    Review fix after commit 25: the matrix failed only the backup's file key and salt reads, and a silent zero
    fallback on its nonce and file-name reads passed every gate and test. `every_os_read_of_a_ceremony_halts_and_wipes`
    now runs one whole Mixed phone ceremony from a pinned list of its 8 OS reads (OS record 64, nonce 8,
    passphrase 11, one challenge attempt 16, file key, salt, nonce 16 each, file name 4): each read fails in
    turn (`FailAt`) and comes up one byte short in turn (`ShortAfter`), halting its own step with the exact
    error and one wipe, and with every listed read served the ceremony completes, so a new draw site cannot
    stay off the list. The zero fallback fails it at read 6.
  - check_flow: as planned, plus lenient code entry (`pbjn yzy5`), vector 1's code refused as another seal's, the
    UR proof of another bucket, the current, stale and future snapshots as well as proofs, and one snapshot,
    loaded once, that stops the 50-roll seed and then clears the 99-roll seed after the restart.
  - ceremony: the matrix of Mixed and dice-only, Pi and phone, 12 and 24 words, each read back letter by letter
    from its faces (up to the first blank face) with the gate shut until the last word; C recomputed from the
    revealed D; the backup opened by `decrypt_backup` with the session's fingerprint, words, braille lines (device,
    sequence, SeedBook number, cells) and seal; the registration and the plain export. The TREZOR checks run in
    two of the eight (12-word Mixed Pi, 24-word dice-only Pi) to bound the scrypt runs. Review fix after commit
    25: Mixed mode's words come from real OS randomness, so the words, braille lines, fingerprints and
    registration are compared with `assert!` and a message; `assert_eq!` printed both word lists on a failure.
- [x] `tests/no_secret_text.rs` (build-plan.md CI rule "Secrets never printed"; the refined rule goes to the owner as
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
- [x] `tests/panic_wipe.rs` and `tests/no_panic.rs`:
      - a thread panics while holding a stub session: `join()` is `Err`, and the probe shows one wipe;
      - deterministic truncations and byte flips (SHA-256 counter mode) of hwrng input, faces, go-ahead codes, proofs
        (bytes and UR text), snapshots, `.age` files, typed backup words and read-back strings give errors, never a
        panic.
- [x] `tests/vectors.rs` runs the full sets: 24 BIP39 seeds, 26 CCTV files, 3 seal vectors, 2,048 braille entries,
      watchonly.json, kcr.json, backup.json and rolls.json. `tests/kat.rs` cross-checks the KAT subsets.
      Approved as built 2026-10-10 (owner item 9): the placement (a) and the 16 of 24 BIP39 seeds (b), below.
- As built at commit 25 (no_secret_text, panic_wipe and no_panic declare `required-features = ["test-sources"]`;
  vectors and kat run with default features):
  - no_secret_text: five ceremonies run end to end on stubs: dice-only from Coldcard's 50 (12 words), 99 (24) and
    100 rolls (12), and two Mixed ones. keepcrypt.json's "mixed" cases fix D directly, which no session can take
    (D comes only from the pool), so the Mixed ceremonies are keepcrypt.json's source-substitution sessions (Pi, 12
    words; phone, 24 words), whose D is known. Each transcript formats with `{:?}` (and `{}` where implemented)
    every public value the ceremony gives (settings, credit, C, the dice counts, the seal and its strings, the
    check request, a typed code and its `Rejected`, the fingerprint and first address, read-back errors, the
    backup file name and `verify_backup`'s result, the checked backup's fingerprint and seal, the registration's
    and the collision report's URL, grouped code and Seal ID, the export's fingerprint, xpub, descriptors, UR,
    QR text and first address) plus a fixed text shared by every transcript: each variant of the public enums,
    every `CoreError` listed through exhaustive matches, and every `CheckError`. Check 1 matches a seed word as a
    whole token on both sides; the control is the first other ceremony with no word in common. Review fixes
    after commit 25: check 1 used case-folded substrings, which this note called "stronger than a whole token";
    on the excusing side it was weaker, since a seed word the control prints only inside a longer token ("keep"
    in "keepcrypt") was excused, so lone leaks of "you", "keep" (the Pi session) and "any" (the phone session)
    passed all three checks. Each is now planted and caught, and only "tag" and "draw" stay excused, as whole
    tokens of the fixed text. `CheckError`, the registration, the collision report and the export's strings were
    not formatted. The `Debug` of `VerifiedSnapshot` and `VerifiedProof` is left out on purpose: both come from a
    registry file alone and are the same in every transcript, and their dates' field names would excuse "day"
    and "month" from check 1. Check 2 looks for adjacent tokens, check 3 for whole tokens over
    the full BIP39 list, on `Rejected::Retry` (malformed, wrong, another bucket), `Rejected::Collision` and both
    discards' `Wiped`, with `{:?}` and `{:#?}`. Each check catches its planted leak: a leaking `Debug` printing one
    word (check 1), two consecutive words whose single words the control also shows (check 2, which check 1
    passes), and `Session` and `report` in a hand-written `Debug` (check 3). Mutant check: `Rejected`'s `Debug`
    printing `Session<Checking>` fails check 3.
  - panic_wipe: a thread panics while holding a stub session in Collecting, Rolling, Checking and Ready (words
    shown, one read back): `join()` is `Err` and the probe shows one wipe; a thread that ends normally wipes once
    without a panic.
  - no_panic: truncations and replaced bytes chosen by SHA-256 counter mode: hwrng chunks (truncated, changed,
    stuck, 1 MiB), dice faces (0, 7-255 samples, a 257th roll), 116 go-ahead codes on one checking session (every
    one a `Retry`), every truncation and 1,024 changed bytes of a KCP1 proof, every truncation and 512 changed
    characters of its UR text (every one refused), every truncation of a snapshot and 64 changed bytes of its
    signed part, plus two changed entries (each costs a full root pass), the binary and armored abandon backups
    (every truncation and 256 changed bytes of each; none opens except the armored file without its final LF,
    which is backup.json's `abandon-12-no-final-newline` and opens by design), typed backup words, read-back
    strings at all 256 positions, odd BIP39 passphrases through `watch_only`, and registry dates. Review fix
    after commit 25: the armored file was tried at every fourth truncation only, which skipped that one.
  - vectors.rs runs every set the public API reaches: rolls.json and the six keepcrypt.json dice-only cases
    through dice-only sessions at both lengths (`TooFewRolls` below the minimum), every backup.json and age CLI
    file whose passphrase is eight list words through `decrypt_backup` (13 open to their plaintexts; 12 since
    d8b5d25, the 8 backup.json backups and the age CLI's 4; the 4,096-byte
    payload is `Backup(Plaintext)`, every refused file gives its exact error), seal.json's vector 1 through a
    checked backup's `seal()` (every public field), and braille.json's entry for every word those seeds and backups
    hold. Deviation, raised as an owner item after commit 25 ("Raised by the review of commits 22-25") and
    approved as built on 2026-10-10 (owner item 9): secrets
    have no public constructor (CLAUDE.md rule 5), so no integration test can reach the rest; each stays in the
    unit tests of its module, which read the same files: BIP39 vectors.json's 16 12- and 24-word entries
    (seed.rs: the words, the TREZOR seed derived through `passphrase_seed_into`, and the master fingerprint; until
    the review fix after commit 25 it copied the published seed in, and core derived only entries 0 and 23), the
    26 CCTV files, whose passphrase "password" is not eight words (backup/age.rs), seal.json's vectors 2 and 3
    (seal.rs), the 2,048 braille entries (braille.rs) and watchonly.json (descriptor.rs, ur.rs). kcr.json is
    tests/kcr.rs and tests/kcr_release.rs. BIP39 vectors.json's other 8 entries have 18 words, a length core
    never makes: the Bip39 KAT checks their words through the bip39 crate and verify.py checks every entry's
    words, but nothing recomputes their seeds.
  - kat.rs: kat.rs's unit tests already compare every constant with its file, so this test checks from outside
    that the files agree on the answers the groups share (seal.json vector 1 and kcr.json's vector-1 seed with
    CLAUDE.md's seal and go-ahead vectors, the abandon fingerprint in watchonly.json and backup.json, the dice-only
    E of `123456` in keepcrypt.json and rolls.json, RFC 8032 TEST 1 in kat.json and kcr.json, CCTV's two files in
    backup.json, braille.json's caption and seal.json's) and that `self_test`, `hwrng_boot_test` and
    `decrypt_backup` give them.
  - Line coverage of core, `cargo llvm-cov --locked -p keepcrypt-core --features test-sources --no-cfg-coverage
    --fail-under-lines 95` with cargo-llvm-cov 0.9.1: 97.40% (8,199 lines, 213 missed); the CI job is commit 27.
    After the review fixes after commit 25 (at 96dca19): 97.39% (8,248 lines, 215 missed), exit 0.

**11. Release artifact scan** (build-plan.md CI rules "One RNG path in shipped binaries", "Test stubs never ship";
moved from M0)
- [x] `scripts/banned-api-check.sh --artifact TARGET FILE...`. The script already owns the banned names and is
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
- [x] `core/examples/release_probe.rs` (default features): self-test, a Phone ceremony with fixed public dice,
      `start_check`, read-back, then `generate_backup_passphrase` and `encrypt_backup`, so every OS draw site is
      linked. It also calls `registry_key_is_test()` and `verify_snapshot` on public test bytes (expecting
      `NoRegistryKey` in release), so a `test-registry` build links the registry-key path and its marker. It prints
      nothing. Proof: the cross job scans the release rlib and the probe for all six targets.
      CI on 34beea2 (run 38041799043) scanned the rlib and the probe clean on all six targets (Review, "M1: the
      owner's answers applied"); reviewed and ticked 2026-10-10.

**12. CI, canaries, coverage, commands** (Q11)
- [x] CI jobs, 11 today and 13 after M1 (they become required checks only through the Q12 ruleset):
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
      On 4733e4a every job passed except age-interop against 1.1.1 (fixed in d8b5d25); on 34beea2 (run 38041799043)
      all 14 check runs passed (Review; reviewed and ticked 2026-10-10).
- [x] `scripts/canaries.sh`, with its pinned counts updated:
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
- [x] Coverage: `cargo llvm-cov --locked -p keepcrypt-core --features test-sources --no-cfg-coverage
      --fail-under-lines 95`, with cargo-llvm-cov 0.9.1. No `#[coverage(off)]` and no `cfg(coverage)`. CI fails if any
      path under core/src matches `/(tests|examples|benches)/`, or any core/src file is named `tests.rs`,
      `*_tests.rs` or `*-tests.rs`, because the tool's default ignore rule skips all of those.
      97.39% locally and in CI's coverage job on 34beea2 (run 38041799043, Review; reviewed and ticked
      2026-10-10).
- [x] CLAUDE.md "Commands" gains:
      - the feature test run and the coverage command;
      - each `--write-*-vectors` flag (regenerate, never hand-edit);
      - `banned-api-check.sh --artifact` and `scripts/age-interop.py`;
      - the `TRYBUILD=overwrite` line.
- As built at commits 26-28 (68ec043, a421d12, 4cea8ba, cfdb24a):
  - The probe passes the check as a user would: it reads n from the check URL, works out G itself (SHA-256 through
    sha2, a core dependency) and reads every word back. It exits with a code per step and prints nothing. Under
    `test-registry` its `verify_snapshot` of kcr.json's "empty" snapshot verifies, so the canaries run that probe too.
  - Not in the plan's words: `TEST_REGISTRY_KEY` became a `#[used]` static read back through `black_box`, like the
    marker (68ec043). As a const, the compiler may split its 32 bytes into immediates or constant-pool chunks on
    some targets, and the scan looks for them in one piece. Under default features neither item exists.
  - The scan also fails a file that is not ELF, Mach-O or ar (`Format`), so a text file holding a marker gives two
    hits; checks archives (core's rlib) for every rule but the OS import, which the getrandom crate's own rlib
    makes; checks rand-family paths in every symbol, defined or not; and has a host rule for macOS (`_getentropy`,
    which getrandom calls there), so the positive controls run on a Mac. Q8's fallback symbols are any symbol in
    getrandom's `backends::use_file` and `backends::linux_android_with_fallback`.
  - The selftest goes beyond the three object cases and the two marker files: a getentropy import (a hit on
    Android, allowed on iOS), a crate named rand, a getrandom fallback symbol, two archives, the key's bytes, two
    files at once and three errors, each with its exact hit lines, and the pinned key checked against kcr.json.
  - canaries.sh also has a mutation canary for the graph pins (serde in core, getrandom in the FFI and
    `legacy_compatibility` on ed25519-dalek, each named), a default-features control (scan clean, probe exits 0)
    and a run of the test-registry probe; the vectors-tamper canary covers `age/age_cli_written.json` too (8
    files). canaries.sh had no count to update, so "with its pinned counts updated" became a pin of the number of
    checks run (54): a deleted or skipped check now fails too.
  - The workflow's changes job (Q12) diffs a PR's merge commit against its first parent, or a push against
    `github.event.before` (passed through env), and counts an unreadable range as a change. The cross matrix skips
    its steps, not the job: a skipped matrix job reports one check under its unexpanded name, which a ruleset could
    not require per target. 9 jobs and 14 check runs (cross has 6 legs): the plan's 13 plus the changes job, which
    a ruleset must also require, since skipped counts as passing.
  - CLAUDE.md Commands also gained the all-features clippy line, which CI has run since commit 4.
- Review fixes after 29 (findings on 26 and 27; proof under Review, "M1: review fixes after 29"):
  - the scan matches all 13 RNG crates of deny.toml's rule-1 block, not the 5 the plan lists, and its selftest
    checks the two lists agree; it also hits glibc's reentrant draws and the rand48 seeders (`random_r`, `srandom_r`,
    `*rand48`, `seed48`, `lcong48`, `initstate` and `setstate`, each also with `_r`), and fails a thin archive as
    `Format`, since one holds its members' paths and not their bytes (d283a36);
  - the changes job decides by `git diff --quiet --no-renames` over `Entropy/` and the workflow file, from the repo
    root, so a move out of Entropy/, a name git prints quoted and a list longer than a pipe buffer all count as
    changes (216b0a1);
  - the coverage job's path check also has the tool's `/rustc/<hex or x.y.z>/` rule (de93cbc).

**13. Review**
- [x] Paste under Review:
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
      The six scans and the age-interop run against 1.1.1 come from CI on 34beea2 (run 38041799043), pasted under
      "M1: the owner's answers applied" with the ruleset; everything else is under Review. Reviewed and ticked
      2026-10-10.

**Carried to later milestones** (record in their plans)
- M3, M5, M6:
  - a shell that drops `Wiped` and calls `Session::new` resets the 99-roll minimum, so ceremony tests must assert
    "99 after Stop", and "99 after a Cannot check" in the restart after a collision (owner item 5); after a Stop or
    a Cannot check the shells offer only `Wiped::restart`;
  - a pi/app test asserts `Platform::Pi`;
  - builds that talk to the local test registry turn on `keepcrypt-core/test-registry` from the command line with
    `-p`, never in a manifest and never `test-sources`; their scan shows the registry marker and no stub marker;
  - the Pi shows the snapshot's or proof's date and asks the user to confirm it before `reveal`; phones warn on Stale
    and Future. A ceremony test asserts each;
  - the Pi's step 4 bar uses `hw_bytes_tested` and `HW_BYTES_NEEDED` (M3).
- M3 (the waiting-screen games), before any game code: the owner's answer to open owner item 12. pi-firmware.md
  and CLAUDE.md rule 1 have the Pi games call getrandom themselves, but canaries.sh's graph pin allows no getrandom
  dependent except keepcrypt-core, so a pi/app that depends on getrandom turns CI red. Either the pin and its
  mutation canary change in a reviewed commit, or the games take bytes from a core API, and then rule 1,
  pi-firmware.md and banned-api-check.sh's pi/app/src/games exemption change to match.
  Answered 2026-10-10: (b). 73abaea changed rule 1, pi-firmware.md, mobile-apps.md and seal-watchonly-braille.md and
  removed the games exemption; 2441d39 puts the call in build-plan.md's `source` row and sketch. The graph pin stays.
  M3 builds the call before any game code ("Notes for later milestones").
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
- M7: the library residuals the owner accepted as an M7 audit note (owner item 6; "Notes for later milestones").
- M9:
  - the real registry key and origin;
  - the release scan fails on `registry.invalid`;
  - registry key rotation: verify a rotation statement signed with the old key (seal-watchonly-braille.md "Registry
    service spec", "Signing key"). M1 pins one key per release;
  - the checking page's re-check mode for `#t=` without n.

### Verification
- [x] All vectors pass, including the seal vector in `CLAUDE.md`: kat, keepcrypt, braille, seal, watchonly, kcr and
      backup JSON; BIP39 vectors.json; all 26 CCTV age files; rolls.json. `verify.py --selftest` passes all 11 checks
      on 3.12 and on `/usr/bin/python3` 3.9, and its embedded word list hashes to `2f5eed53...` with the banned-API
      gate clean. BIP39 vectors.json and tests/vectors.rs as approved on 2026-10-10 (owner item 9): core derives the
      16 12- and 24-word seeds, and every entry's words are checked.
- [x] Source-substitution test: a fixed stub gives a known D, and changing one stub byte changes D (every source, Pi
      and Phone). A real-OS test shows two sessions differ.
- [x] Pipe width: every single-bit flip of D changes C and E, every bit of the 64-byte OS record changes D, and every
      bit of E changes the 24-word indices.
- [x] Error-injection test for every source and health test: the session halts and wipes, with the exact error and
      one wipe each. This includes every KAT at session start and at restart, and every KAT group of each free
      function through its fault twin.
- [x] `trybuild` compile-fail tests: dice before commit, reveal before finish, mnemonic/D/backup/export in the sealed
      or checking state, skip after a check started, a typed passphrase passed to `encrypt_backup`, plus every other
      fixture in group 10.
- [x] Go-ahead tests:
      - the vector in `CLAUDE.md` passes;
      - a code for another T or nonce is rejected;
      - forged, truncated and wrong-bucket proofs are rejected, and so is every UR decoder negative;
      - a proof containing T wipes the session;
      - a typo can be re-entered;
      - stale and future-dated proofs report their freshness.
- [x] Snapshot tampering: every kcr.json negative, and the header bit-flip sweep, are rejected. Release builds give
      `NoRegistryKey`.
- [x] Dice-only output equals Coldcard `rolls.py`/`rolls12.py` for the fixed roll strings, in core and in verify.py.
- [x] Backup:
      - the CCTV classes match;
      - the writer equals CCTV byte for byte;
      - core reads age 1.1.1 files, and age 1.1.1 decrypts fresh core files at log2 N 18 (age-interop job);
      - only a generated passphrase can encrypt, and `decrypt_backup` returns a `CheckedBackup` whose fingerprint and
        seal match.
      The other three bullets are proven locally. The age-interop job against Ubuntu's 1.1.1 failed on 4733e4a
      (fixed in d8b5d25) and passed on 34beea2 (run 38041799043, Review; reviewed and ticked 2026-10-10).
- [x] Braille: the six `CLAUDE.md` inserts match; 279 and 49 are recomputed; read-back catches every mirror flip and
      every blank-face slip.
- [x] Watch-only: the BIP-84 and BCR-2020-015 vectors, the BIP-380 checksums and the runtime self-check pass.
- [x] Secrets never printed: the no-secret-text test passes and catches a planted leak with each check. A panic wipes
      the session, and hostile input never panics.
- [x] The release artifact scan is clean on all six targets; both positive controls fail for their markers, and the
      `test-registry` build holds no stub marker. CI on 34beea2 (run 38041799043, Review) scanned all six clean, and
      its canaries (54) include both positive controls; reviewed and ticked 2026-10-10.
- [x] Line coverage in `core/` is at least 95% (`cargo llvm-cov`), with nothing excluded: no core/src path matches the
      tool's default ignore rule.
- [x] Clean: clippy (default and all features), fmt, deny, audit, vet, check-path-deps, the banned-API gate and its
      selftest, and the canaries. CI is green on `m1-core`. The Q12 ruleset is in place, or its deferral is recorded.
      All clean locally at 34beea2, CI green on 34beea2 (run 38041799043, Review), and ruleset 24833307 is in place.
      Reviewed and ticked 2026-10-10.

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
| poly1305 | 0.9.1 | 2026-07-08 | via; also a direct edge since b4871b9 (2026-10-10, owner item 6), `default-features = false`, `zeroize` | Apache-2.0 OR MIT | Poly1305; the direct edge only switches on `zeroize` | none |
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
| cargo-llvm-cov (CI tool, not a dependency) | 0.9.1 | 2026-09-06 | `cargo install --locked` into ~/.cargo-tools | Apache-2.0 OR MIT | the 95% line-coverage gate; never in the device graph. Its default ignore rule skips `tests/`, `examples/` and `benches/` directories, `rustc/<hex or x.y.z>/` directories anywhere in the path (found in review after 29) and `tests.rs`, `*_tests.rs` and `*-tests.rs` files, so CI fails if core/src has any such path | its own lockfile has no rand, log or network crate (designer check) |
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
   Review fixes after 21, each its own commit, vectors first:
   - core: the backup tests pin encrypt_backup's file key to the first 16 OS bytes (the file equals the writer's output from them) and show two backups' file keys differ, neither equal to its salt or nonce;
   - core: the backup tests isolate verify_backup's word check, pin decrypt_backup's KAT-first order, and read seal.json's vector for the abandon files;
   - core: every single-bit flip of a binary backup is tried and refused (5,464), not one bit per byte;
   - verify: the armor reader accepts an END line ended by a lone CR at the end of the input, as core and age do (backup.json gains abandon-12-end-cr);
   - verify, core: the armor readers refuse the whitespace the age CLI refuses (at most 1,024 bytes before BEGIN in whole lines, fewer than 1,024 after END; backup.json's vectors and core's reader in one commit, or that commit would be red; changed 2026-10-10 in d8b5d25: none before BEGIN, since age 1.1.1 reads armor only at byte 0);
   - scripts: age-interop.py gives the age CLI every backup.json age file the readers accept;
   - core: the plaintext reader refuses a bad BIP39 checksum as the file's fault and keeps core's derivation faults Internal (Q13 (b) handed to commit 22);
   - core: the age residuals name Poly1305's one-time key and scrypt's PBKDF2 key block, for the owner;
   - this file: the age 1.3.2 files and Q1 (iii)'s upstream issue as open owner items, commit 27 running `--core`, the 1,726-byte figure, and these records.
22. core: session transitions, Wiped::restart, the read-back gate and the panic policy
23. tests: trybuild typestate suite with pinned .stderr files, including the typed-passphrase and CheckedBackup fixtures
24. tests: source substitution, real OS path, error-injection matrix (with the free-function KAT fault twins and the 1,535-byte quota case), check flow (with proof freshness) and full ceremony
25. tests: no-secret-text (control-seed rule plus the BIP39-token check on Rejected and Wiped), panic wipe, no-panic sweeps, and the full vector sets
   Review fixes after 25, each its own commit:
   - core: bip39_vectors_json derives the 16 published TREZOR seeds through passphrase_seed_into;
   - core: a test pins that Cannot check after a collision restarts at the normal minimum (reversed 2026-10-10 by e87b296, owner item 5: now `cannot_check_after_a_collision_keeps_99_rolls`);
   - core: the wipe probe counts a completed zeroize (Inner's Zeroize bumps it last and Drop runs it), and HealthTester derives ZeroizeOnDrop;
   - tests: error_injection fails every OS read of a whole ceremony in turn, from a pinned list, the backup's nonce and file name included;
   - tests: no_secret_text's check 1 compares whole tokens on both sides, with a planted leak for each word a substring match hid, and formats CheckError and the seed-derived registration, collision-report and export strings;
   - tests: ceremony.rs compares the real-OS seeds' words, braille, fingerprints and registration without printing them;
   - tests: no_panic tries every truncation of the armored backup and pins the one that opens; source_substitution's message says 8 credited chunks, not 9;
   - this file: these records, commit 22's coverage figure (97.37%, not 97.29%), and the tests/vectors.rs deviation as an owner item.
26. scripts: banned-api-check.sh --artifact (both markers and the test key) with selftest fixtures; core/examples/release_probe.rs; canaries (two positive controls, static checks for serde, getrandom and the dalek features, vectors tamper; the feature and profile checks landed after 5)
   As built: two commits, 68ec043 (core: the probe, and the test key as a used static) and a421d12 (scripts: the scan, its fixtures and the canaries)
27. ci: coverage job (cargo-llvm-cov 0.9.1, failing on any core/src path its default ignore rule would skip), cross-job artifact scan with the per-target getrandom cfg, age-interop job (`scripts/age-interop.py --core` against Ubuntu's age 1.1.1, so core reads 1.1.1's files and 1.1.1 reads core's), and selftest moved after the toolchain install
   As built: 4cea8ba, which also drops the paths filter and adds the changes job (Q12)
28. CLAUDE.md: Commands for M1 (cfdb24a)
29. tasks/todo.md: M1 Review with pasted proof, including the Q12 ruleset output or its deferral
   As built: 98e3fe5 (the ruleset deferred to the owner, open owner item 1)
   Review fixes after 29, each its own commit:
   - scripts: the artifact scan names all 13 RNG crates of deny.toml (the selftest checks the lists agree), glibc's reentrant draws and the rand48 seeders, and fails a thin archive (d283a36);
   - ci: the changes job decides by git diff's exit code over the two pathspecs, so moves out of Entropy/, quoted names and long lists all count as changes (216b0a1);
   - ci: the coverage job's path check adds the tool's rustc/<hex or x.y.z>/ rule (de93cbc);
   - this file: these records and their proof, and the Pi games' getrandom as open owner item 12 and an M3 carry (4733e4a).
   The owner's answers to the 12 items and CI's age 1.1.1 failure on 4733e4a, each its own commit (proof under Review, "M1: the owner's answers applied"):
   - verify, core: the armor readers refuse whitespace before BEGIN, since age 1.1.1 reads armor only at byte 0 (d8b5d25);
   - docs, then core: after a collision, Cannot check keeps the 99-roll minimum until a check passes (dc53b8f, e87b296; item 5);
   - docs, then core: poly1305 named in build-plan.md, then a direct edge with `zeroize` (0ac7394, b4871b9; item 6);
   - docs: 99 rolls give about 256 bits (012c8db; item 4); the Public API sketch matches the built API (62e2e5e; item 10);
   - rule 1: games get their bytes through core (73abaea; item 12 (b));
   - review fixes: the poly1305 pin per target (7c46d93), the note under the seed-pipeline figure (6ba465c), the game call placed in build-plan.md (2441d39), the Cannot check branch in the Pi and phone flows (34beea2);
   - this file: the owner's answers, the armor fix, these commits and their proof.

## M2: Offline verifier (`tools/verify/`)

### Inputs from M1 (folded into the plan below)
- Rules are cited from the clone's `Entropy/CLAUDE.md`. The copy in the old `Entropy-Keep Crypt` folder predates
  rule 1's game-randomness call, rule 10's `test-registry` text and the current Commands list.
- verify.py at 90b6ab9 is 5,636 lines, standard library only. Its modes are `--selftest` (11 checks, `selftest` at
  5542), seven `--write-*-vectors` and `--vectors-dir` (`main`, 5589-5632). It has no user mode; line 33 says "The
  verifier's own recomputation of a device's C, E and words, and braille, arrive in M2".
- The primitives a verification run needs exist and are checked against committed vectors: `bip39_seed` 1219, the seal
  family `seal_code` to `go_ahead_code` 1255-1316, `counter_stream` 1427, `bip39_words` 1434, `health_test` 1468,
  `device_leg` 1509, `commitment` 1514, `mixed_entropy` 1519, `dice_only_entropy` 1525, `session_records` 1530,
  `braille_mirror_partner` 1743, `braille_text` 1751, `seedbook_faces` 1787, `insert_positions` 1805. The two entropy
  functions only `.encode("ascii")` the rolls: no 1-6 check and no count check.
- Missing: any input parsing; the check, re-check and register URL builders (verify.py has no `registry.invalid`;
  core builds them from `REGISTRY_ORIGIN`, seal.rs:74, with `/check#t=` and `/register#c=`); a self-check that runs
  without the repo. Today's checks need the repo (`REPO_VECTORS_DIR` 90, `SEEDBOOK_PDF` 93, `BRAILLE_DOCS` 94,
  `DOCS_DIR` 5090), and check 4 runs Coldcard's scripts through `subprocess` (`run_coldcard_script` 5434).
- A release copy of today's file breaks two rules (build-plan.md "Release": "A single Python file"):
  - rule 10 ("CI fails any release artifact that contains either marker, the test registry key ..."): it holds the
    label `KCE/test/registry-key/v1` (855), the test public key `42e9fa0e…` (`KCR_PINNED`, 889) and the label-key
    signer `ed25519_secret`/`ed25519_sign` (2636-2660);
  - rule 8: `write_vectors` (1354; the file's only write-mode `open`, 1358) writes seven JSON files, and checks read
    JSON, Markdown and the SeedBook PDF (5354, 5389 and the repo paths above). `age_encrypt` (3628) writes no file:
    it returns bytes. It moves to vectorgen only because it exists to build vectors, including the refused
    non-final chunk.
  `_AGE_SCRYPT_CACHE` (3457) also keeps every passphrase and wrap key for the life of the process; harmless while only
  test files pass through it.
- Provenance names the generator. Each of the seven generated files has a `description` naming its command ("Generated
  by tools/verify/verify.py --write-seal-vectors; verify.py --selftest regenerates this file ..."; seal, kat,
  keepcrypt, braille, watchonly, kcr and backup .json). `vectors/age/age_cli_written.json` says "verify.py --selftest
  reads their armor and headers (check 11)". vectors/SOURCES.md names verify.py on 39 lines (its commands at 5, 9,
  12, 18, 29, 43, 55, 83 and 291). Six core comment lines name verify.py commands, checks or its signer:
  health.rs:6, seed.rs:511, seal/registry_key.rs:8 and :116, test_vectors.rs:2, tests/common/mod.rs:3.
  age_cli_written.json comes from the age CLI with fresh random keys (`scripts/age-interop.py --generate`,
  SOURCES.md:112, hash row `29ba3cbc…`), so its text cannot change unless the file is regenerated.
- verify.py has seven writers. The eighth file in canaries' tamper loop, age_cli_written.json, is the age CLI's.
  The bip39, coldcard and CCTV age/scrypt files are fetched, with SOURCES.md hash rows.
- `scripts/age-interop.py` loads verify.py by path (`load_verify`, 58) and calls `backup_passphrase_indices`,
  `backup_passphrase_text`, `age_decrypt`, `BackupRefused`, `age_armor`, `age_encrypt`, `age_parse_header`,
  `age_dearmor`, `age_scrypt_stanza`, `BACKUP_WORK_FACTOR` and `hashlib` (lines 123-306).
- canaries.sh: the tamper loop (837-875) runs `python3 -I verify.py --selftest --vectors-dir` once for each of 8 files
  (the seven generated ones and age_cli_written.json), and `want_checks=54` (954). Its workspace copy `$work/repo`
  (118-126, without target/ and .git/) already serves the real-crate clippy canaries.
- CI (`.github/workflows/entropy-ci.yml`): `gates` runs `python3 tools/verify/verify.py --selftest` (220, no `-I`);
  `verifier-py39` runs it with `/usr/bin/python3` (267; timeout 10 minutes; macOS); `test` step 2 runs `cargo test -p
  keepcrypt-core --locked --features test-sources` (158); coverage 319; age-interop 359. Run 38041799043: gates
  3m36s, verifier (python 3.9) 26 s, test 4m55s. Both verifier jobs are required contexts of ruleset 24833307 (Q12).
- Python 3.9 floor: macOS `/usr/bin/python3` 3.9.6 on LibreSSL 2.8.3 has no `hashlib.scrypt`, and `scrypt_pure` is
  "never for 18" (3440). Measured while planning, in scratch copies: about 3 minutes and about 2.5 GB at log2 N = 18;
  verify.py's affine secp256k1 costs about 35 ms per key multiply (`watch_only_wallet` about 330 ms). Measured: the
  maths of 1,000 agreement cases (C, E, words, S, seal, G, braille) takes 0.99 s on 3.9 and 0.47 s on 3.12, and
  health-testing 250 hwrng streams of 4,096 bytes takes under 0.1 s.
- getpass on 3.9.6 (`inspect.getsource(getpass.unix_getpass)`): it reads `/dev/tty` first and stdin only if that
  fails. It writes the prompt to the tty unless `stream=` is given, sets no-echo with `TCSAFLUSH`, which drops input
  typed ahead of the prompt, and raises `EOFError` at end of input. `pty.fork()` and `sys.addaudithook` exist on 3.9
  on Linux and macOS. Measured: `getpass.os.open`, `getpass.io.open`, `argparse._os.system` and `sys.modules` are
  reachable with no banned import or call, so an import allowlist alone keeps nothing away from files or processes.
- Core needs no new API. Under `test-sources`, `Session::new_with_stub` (session.rs:185) with `StubEntropy::Fixed`
  (stub.rs:27; a read past the end fails closed, 99-110) drives every ceremony. Public calls reach every compared
  value: `commitment()` 264, `seal()` 313, `check_request()` 337 (`url()`, check.rs:74), `reveal` 347, `discard` 361,
  `mnemonic()` 368, `braille()` 374, `check_readback` 392, `registration()` 452, `reveal_device_leg()` 460 and
  `seal_from_mnemonic` (seal.rs:309).
  - Stub reads: core reads the stub in a fixed order: 64 bytes at `commit` (Mixed only), then 8 at `start_check`.
  - Rolls: `push_roll` refuses a face outside 1-6 (`InvalidRoll`) and a 257th roll (`TooManyRolls`); `finish`
    refuses too few (`TooFewRolls`). Extras are ignored in dice-only mode (inner.rs:129).
  - Collisions: `discard(Discard::Collision)` keeps the collision report (`collision_report()`, with `url()` and
    `grouped_code()`, seal/registration.rs:73-87) and a 99-roll minimum for either length (`MIN_ROLLS_AFTER_COLLISION`,
    dice.rs:24). `Wiped::restart_with_stub` (session/wiped.rs:133, test-sources) restarts on a fresh stub.
  - Go-ahead codes: `reveal` forgives case, dashes, spaces and O/I/L in G (wiped.rs:43). A symbol outside the alphabet
    is `MalformedCode` (seal/crockford.rs:80-101); only a different valid value is `WrongCode`.
  - Braille: each insert exposes `position`, `device`, `device_count`, `sequence`, `seedbook_number`, `word`, `faces`
    and `word_cells`. Each face exposes `is_blank`, `letter`, `cell`, `dots` (`Dots::bits`), `is_lighter` and
    `mirror_partner` (braille.rs:118-410).
  - E: core has no accessor for E (`seed_entropy` is private, inner.rs:64). The words fix exactly the seed bits.
  - Existing coverage: core's seed.rs tests check every keepcrypt.json `commitment` and `mixed` case (395-496).
    `common::read` reads the fixed path `../vectors` (tests/common/mod.rs:8-12).
  - Cost: measured in a scratch copy, 1,000 stub ceremonies take 7.19 s serial, 6.05 s of it the known-answer suite
    at each session start. no_panic.rs:23 has a 10-line counter-mode helper to copy.
- R is exactly the ASCII digits 1-6 (M1 "Inputs from M0"). rolls.py:202 runs `input().strip()` and hashes what is left;
  it prints E in hex, then the words, and only warns below 99 characters. rolls12.py:202-204 prints only
  `sha256(r.encode()).digest()[:16]` in hex, then the words, and warns below 50. Neither has a maximum. rolls.py:3
  documents `echo 123456123456 | python3 rolls.py`.
- The banned-API gate's `network()` (256) and `clipboard()` (289) have no Python patterns.
- The docs leave open how D is shown (pi-firmware.md:95, mobile-apps.md:183), while C is "16 groups of 4 hex
  characters" (pi-firmware.md:86, mobile-apps.md:174). design.md:242 says "record D or the rolls"; a mixed run needs C,
  D and the rolls (mobile-apps.md:186). design.md:215: for 12 words the seed is the first 128 bits of E, "so dice-only
  output matches Coldcard's rolls12.py".
- What earlier milestones expected of M2: "Carried to later milestones" covers M3-M9 only, but two lines expect more.
  - M1 Q3 (ii), approved 2026-10-09, put Ed25519 in verify.py because "M2 needs this for re-checks" (todo.md:90-91).
  - M0 said "M2 grows it into the full verifier" (todo.md:604).
  - seal-watchonly-braille.md:164 also names the verifier as a re-check tool.
  This plan moves re-checks to M9 and asks the owner to confirm (Q22).
- Other owner items: 13 and 14 do not touch M2 (14, the 99-roll minimum lost on in-RAM wipes, is recommended for M3).
  The optional 18-word seed recompute (owner item 9 (b)) stays unplanned.
- CODEOWNERS covers every path M2 changes: `/Entropy/tools/verify/`, `/Entropy/vectors/`, `/Entropy/core/`,
  `/Entropy/**/Cargo.toml`, `/Entropy/scripts/`, `/.github/`, `/Entropy/CLAUDE.md` and `/Entropy/docs/`.

### Plan
Refs: docs are named by file (build-plan.md, design.md, seal-watchonly-braille.md, pi-firmware.md, mobile-apps.md,
all in `docs/`), plus CLAUDE.md, lessons.md (`tasks/lessons.md`) and this file. Q1-Q15 are M1's questions; Q16-Q24
are this milestone's, under "Needed before M2 code" at the top of this file. Symbols as in CLAUDE.md: D, C, R,
E, S, T, n, G.
- "verify.py" is the shipped `tools/verify/verify.py`; "vectorgen" is `tools/verify/vectorgen.py`, the repo-only
  generator and self-test that never ships (Q16).
- "Check N" is `vectorgen.py --selftest` check N. Checks 1-11 are M1's, unchanged.
- "Lone copy" is verify.py copied by itself into a new empty directory, with no repo around it.
- "Audited run" is a lone-copy run under check 12's audit harness (group 3, rule (e)).
- "Run" means a verification run (design.md:239-244): a disposable ceremony recomputed on an offline computer.
- "Seed bits" are E[0:16] for 12 words and all of E for 24.
- "Leak rule": the typed D and both output streams are normalised (whitespace and hyphens removed, lowercased), and
  no 8 consecutive hex digits of D may appear. Likewise, after removing whitespace and joining lines, no 12
  consecutive digits of R may appear.

Groups land in the order below. Vectors come before the core test that reads them, and every item names its proof.

**Built into this plan (override any of them)**
- Scope: M2's user commands are `selftest`, `mixed` and `dice`: the verification run of design.md steps 1-3 and
  mobile-apps.md:186. Re-checking a real wallet waits for M9 with the registry key (Q22), so no real seed is typed
  into the verifier in M2.
- One computation path: the CLI, the agreement generator and check 12 all call `verification_run` and `render`. The
  generator hands it C and D as display text, so the 1,000 cases test what a user runs. Only the prompt layer is
  outside the agreement, and check 12 covers it from lone copies, piped and in a pseudo-terminal.
- The verifier writes the cases and core replays them (Q17): `vectors/agreement.json` is committed, and
  `core/tests/agreement.rs` (test-sources) compares every output. No new core API, test hook, CI job or required
  context.
- Test data stays deterministic, never a PRNG (M1's rule):
  - streams are SHA-256 counter mode over public labels `KCE/test/agreement/v1/<case>/<part>`;
  - a dice face is a stream byte b < 252 mapped to b mod 6 + 1; bytes of 252 or more are skipped;
  - each stub (`StubEntropy::Fixed`) holds exactly the bytes core must read, so a missing, extra or reordered read
    changes n or fails closed.
- Output: `entropy:` shows the seed bits.
  - 12 words: E[0:16], exactly the line rolls12.py prints (design.md:215).
  - 24 words: all of E, the line rolls.py prints.
  - The words fix exactly these bits, so core's word comparison covers the whole line. The rest of E is never shown.
- Fail closed in the verifier (rule 3 by analogy with core's session-start suite): every command runs all embedded
  known-answer groups before its first prompt and exits 1 if one fails. If D does not match C, it exits 1, never asks
  for the rolls and computes nothing from D. An unexpected error exits 70 with a fixed line, and Ctrl-C exits 130;
  neither prints a traceback.
- Secrets (rule 5; Q20): input comes only from prompts on stdin, never from arguments, the environment or a file.
  Prompts go to stderr, results to stdout.
  - On a terminal, every field (C, D and each line of rolls) is read with `getpass(stream=sys.stderr)`, without echo.
  - C is then printed back on stderr in 16 groups of 4, in both modes, since it is public. D and the rolls are never
    printed, only their counts.
  - Reading C hidden too means a paste of all three fields at C's prompt is dropped by getpass's flush, never shown.
  - When stdin is not a terminal, one stderr line says the input came from a pipe or file, and to clear it from shell
    history and delete any file.
  - Errors name the field and position, never the text typed.
- Files (rule 8): verify.py opens no file in M2. Check 12 forbids `open` statically, and fails any audited run that
  opens a file outside the interpreter's standard library and the copy itself (plus `/dev/tty` on a terminal).
- The verifier never issues a go-ahead code. G is computed only in its known answers and the vectors, because a
  verifier that printed G for typed T and n would make skipping the check trivial. M9's checker issues codes.
- No new dependency (Python standard library; core's test uses `sha2` and the approved dev dependency `serde_json`),
  no download, no new SOURCES.md "Spec values" entry or copied value (its rows name files as the split leaves them,
  Q16 (b)), and no new computed number in `docs/` (lessons.md rule 1).
- Out of M2: see "Deferred, with their milestone" below.

**0. Before code**
- [x] Record the owner's answers to Q16-Q24, quoted with the date. Apply the approved doc edits (Q19) alone in one
      commit with no code. Proof: the answers in this file; commit 2's diff touches only `docs/`.
      Answers recorded 2026-10-10 under "Needed before M2 code" ("approve all").
      Proof (M2 Review, 2026-10-11): a7c941e records the answers. Commit 2 is 5d222f5, and `git diff --name-only
      5d222f5~1 5d222f5` lists only Entropy/docs/build-plan.md, design.md, mobile-apps.md and pi-firmware.md.
- [x] Baseline at 90b6ab9, pasted under Review and used by group 8's budget:
      - `--selftest` 11/11 on Python 3.12 and `/usr/bin/python3` 3.9.6, with times;
      - canaries 54/54, with wall time;
      - `cargo test` in both configurations.
      Proof (M2 Review, 2026-10-11): pasted under "M2: local proof". It was taken at a7c941e, which differs from
      90b6ab9 only in this file: 11/11 on 3.12.5 (5.6 s) and 3.9.6 (9.2 s), canaries 54/54 in 1:09, `cargo test`
      183 and 251 passed.

**1. Split the shipped verifier from the repo-only generator (Q16 (a); rules 8 and 10; build-plan.md "Release")**
- [x] `tools/verify/vectorgen.py` (new) and `tools/verify/verify.py`, split by one rule: a function stays in verify.py
      if a published computation or reader needs it, and moves if it exists only to build vectors, sign, write, run
      another program or read the repo.
      - vectorgen loads verify.py by path with `importlib` (as age-interop.py:58 does) and uses its names.
      - vectorgen takes: `main` with the seven `--write-*-vectors` and `--vectors-dir`; checks 1-11 and `selftest`;
        the `*_SPEC` dicts and pinned answers; `UNLISTED` and `write_vectors`; the pool and health-test model;
        `counter_stream` and every `KCE/test/` label; the label-key signer and the test public key; the `.kcr` and KCP1
        builders; `age_encrypt`, `age_armor`, and `backup_generate` with the passphrase-from-bytes helpers; and the
        Coldcard runner.
      - verify.py keeps: the embedded word list, BIP39, PBKDF2, C and E, the seal family, braille and inserts,
        secp256k1, BIP32, descriptors and UR, Ed25519 verification, Merkle and `.kcr`/KCP1 verification, the age
        reader and the plaintext v1 parser. Its `main` becomes a placeholder that prints usage and exits 2 (group 7
        fills it).
      - It is a pure move: no algorithm, output or description string changes, and checks 1-11 print the same lines.
      - In the same commit, or it would be red: age-interop.py loads vectorgen; canaries' tamper loop and the two CI
        selftest steps call `python3 -I tools/verify/vectorgen.py --selftest` (the CI steps gain `-I`); CLAUDE.md
        Commands name the new file.
      Proof:
      - the seven files vectorgen writes regenerate byte-identical (`git diff --exit-code vectors/`);
      - age_cli_written.json and every fetched file are unchanged and still match their SOURCES.md hash rows
        (check 3);
      - `vectorgen.py --selftest` passes 11/11 on 3.12 and 3.9 with the baseline's lines;
      - age-interop passes in its default mode and with `--core`; canaries pass 54/54; CI is green on the commit;
      - verify.py imports none of `json`, `os`, `pathlib`, `subprocess`, `tempfile`, `math`, `stat` or `zlib`, and
        both files' line counts are recorded.
      Proof (M2 Review, 2026-10-11): commit 3 is 99edb77. On 3.12.5 and 3.9.6 the seven `--write-*-vectors` modes
      leave `vectors/` byte-identical, and `vectorgen.py --selftest` passes 11/11 with the baseline's lines (check 3
      included). age-interop passes in its default mode and with `--core` (Homebrew age 1.3.2), and canaries pass
      54/54. verify.py has 1,630 lines and imports only base64, binascii, datetime, hashlib, hmac, re, struct, sys and
      unicodedata; vectorgen.py has 4,096. CI runs only on pushed heads: 86c4c0d, the first pushed head that holds
      99edb77, passed all 14 Entropy check runs (run 38061106528).
- [x] Provenance, in the next commit (Q16 (b); lessons.md rule 1, so every committed value still names the script
      that makes it):
      - vectorgen's seven `description` strings name `tools/verify/vectorgen.py --write-X-vectors` and
        `vectorgen.py --selftest`. The seven files are regenerated.
      - SOURCES.md: a mention of a command, mode or check number names vectorgen.py. A mention of a computation, table
        or reader that stays in verify.py keeps verify.py. One sentence records that age_cli_written.json's "verify.py
        --selftest reads their armor and headers (check 11)" predates the split and now means vectorgen.py check 11.
        That file keeps its bytes and hash row.
      - Core comments, comment lines only:
        - health.rs:6, seed.rs:511 and seal/registry_key.rs:8 and :116 name vectorgen.py;
        - test_vectors.rs:2 and tests/common/mod.rs:3 say the computed values come from `tools/verify/` (vectorgen.py,
          computing with verify.py);
        - lines about computations that stay in verify.py (seal.rs:33, ur.rs:14, seal/snapshot.rs:392,
          backup/armor.rs:37) stay as they are.
        The full list is `git grep -n 'verify\.py' -- core vectors` at the commit, with each line's verdict pasted.
      Proof:
      - for each of the seven files, old and new compare byte-equal once both have the `description` value blanked;
      - age_cli_written.json is byte-identical;
      - every changed `.rs` line is a comment (`git diff -U0 -- core` adds and removes only `//` lines);
      - `cargo test` passes in both configurations, and checks 1-11 pass;
      - `git grep -nE 'verify\.py (--write|--selftest|check [0-9])' -- ':/' ':/!Entropy/tasks/todo.md'` (the whole
        repo but this file) finds only the recorded age_cli_written.json sentence and SOURCES.md's record of it.
      Proof: commit 4. Each of the seven regenerated files equals its old bytes with `description` blanked, and
      `git diff -U0` changes line 2 only; age_cli_written.json keeps SHA-256 `29ba3cbc…`; `git diff -U0 -- core`
      changes only `//` lines; the grep finds the age_cli_written.json sentence and SOURCES.md's quotation of it;
      `cargo test` passes in both configurations (183 and 251 tests); vectorgen.py `--selftest` passes 11/11 on
      3.12 and 3.9; canaries pass 54/54.
      Proof (review fixes): at 76dd1fb the whole-repo grep also finds `scripts/age-interop.py:272`, the `--generate`
      template; bbbb599 fixes it, and from there the grep finds only age_cli_written.json:2 and SOURCES.md's record.
      Verdicts for `git grep -n 'verify\.py' -- core vectors` at 76dd1fb (30 lines):
      - kept, code still in verify.py: armor.rs:37 (`BACKUP_WHITESPACE`), seal.rs:33 (the seal family),
        registry_key.rs:30 (the key computed apart from verify.py's Ed25519), snapshot.rs:392 (its Ed25519 verifier),
        ur.rs:14 (the UR writer and reader); SOURCES.md:20 and :30 (the embedded BIP39 list and the cell table), :24,
        :75 and :98 (answers computed apart from verify.py), :53 (the strict UR reader), :70 (the `.kcr` verifier),
        :91, :234, :244 and :310 (the age reader), :143 (the Spec values intro), :172, :174, :175 and :178 (rows
        naming `DESCRIPTOR_*`, `hdkey_item`, `BYTEWORDS` and `AGE_*`), :156 and :160 (its literals and reader beside
        vectorgen.py's), :189 (its Ed25519); backup.json:2 (its reader) and kcr.json:2 (its verifier);
      - changed: test_vectors.rs:3 and tests/common/mod.rs:3, "vectorgen.py, computing with verify.py";
      - recorded: age_cli_written.json:2 (its sentence, kept by Q16 (b)) and SOURCES.md:315 (the record of it).

**2. Python networking and clipboard in the banned-API gate (Q23; CLAUDE.md Commands "network and clipboard APIs")**
- [x] `scripts/banned-api-check.sh`, for `.py` files, dispatched like `pyrandom()`:
      - network: `import` or `from` of `socket`, `ssl`, `urllib`, `http`, `ftplib`, `smtplib`, `poplib`, `imaplib`,
        `telnetlib`, `xmlrpc`, `asyncio`, `webbrowser`, `requests`, `httpx`, `aiohttp`, and of `_socket` and `_ssl`,
        the C modules behind socket and ssl (review fix). Completed by the stage-A review (2026-10-10, F10; commit
        5b): `socketserver`, `urllib3`, `nntplib`, `smtpd`, `asyncore`, `asynchat`, `wsgiref`,
        `multiprocessing.connection` and `logging.handlers`, the last two also by their own names, which `from logging
        import handlers` brings in, so any import of a module or name called `connection` or `handlers` hits. The
        pattern is anchored on the import, so a URL string such as `https://registry.invalid` stays quiet;
      - clipboard: `pyperclip`, tkinter's `clipboard_append`/`clipboard_get`, and `pbcopy`, `pbpaste`, `xclip`,
        `xsel`, `wl-copy` anywhere in a `.py` file. Completed by the stage-A review (2026-10-10, F10; commit 5b): an
        import of the `clipboard` module (in the network shapes); `win32clipboard` and `wl-paste`; in any letter
        case, PowerShell's `Get-Clipboard` and `Set-Clipboard`, `clip.exe` (only with `.exe`, since `clip` is a
        common word) and osascript's `the clipboard`; any `.clipboard` attribute or dotted module
        (QApplication/QGuiApplication `.clipboard()`, also on an application object); pandas
        `to_clipboard`/`read_clipboard`; and tkinter `selection_get`, whatever its selection (`CLIPBOARD` may sit on
        the next line or in a variable, and the default, `PRIMARY`, is X11's other clipboard);
      - recorded residuals: grep cannot see `__import__("socket")`, `importlib.import_module("socket")`, an attribute
        path such as `getpass.os.system`, or a subprocess running a network tool. For verify.py, check 12 closes all
        four: rule (a) bans `__import__`, any `importlib` import and every module attribute outside its recorded list,
        and rule (e) fails any socket or process event in an audited run. vectorgen and `scripts/` keep the grep gate
        only.
      Proof: `--selftest` gains one hit and one near miss per pattern; the gate is clean on the tree.
      Proof: commit 5. `banned-api-check.sh --selftest` passes 297/297 (251 before) under sh and dash: 19
      `network-python-*` fixtures (each module, plus the parenthesised, no-space, backslash-continued and wrapped
      import lines; each also clean under `registry/`) and 8 `clipboard-python-*` fixtures each give exactly one hit,
      and `clean-near-misses/tools/verify/offline.py` holds a near miss for every pattern. The gate before this
      commit finds none of the 27 hits, and a copy whose first network pattern is the bare list `$pynet` and whose
      clipboard patterns drop `${L}` hits 11 lines of offline.py, every line that holds a banned name as text (not
      14, as first recorded). The gate is clean on the tree: 160 files from a clean checkout (`git archive`); a local tree also
      scans the ignored `__pycache__/*.pyc` files that Python runs leave.
      Proof (review fixes): 64c4fc7 adds the line after `from \` and a backslash after the module (network and
      random), 5cc295d adds `_socket` and `_ssl`, and 42d8552 pins the boundaries and the `.py`-only dispatch.
      `--selftest` passes 309/309 under sh and dash; every new pattern, alternative, boundary and dispatch has a
      mutant that turns the selftest red on its own fixture or near-miss line; the gate is clean on the tree.
      Proof (stage-A completion, commit 5b): `--selftest` passes 342/342 (309 before) under sh and dash: 11 new
      `network-python-*` fixtures (each module, plus `from multiprocessing import connection` and a wrapped
      `handlers,` line; each also clean under `registry/`) and 11 new `clipboard-python-*` fixtures each give exactly
      one hit, and the gate before this commit finds none of the 22. offline.py gains a near miss for each new name
      and pattern, and Words.kt a `clipboard,` entry that pins the new import check's `.py`-only dispatch. In scratch
      copies with the artifact selftest stubbed (301 passed), each of 38 mutants (every new alternative, word start,
      end, separator and letter-case class, and the dispatch) turns the selftest red on its own fixture or near-miss
      line. The gate is clean on the tree: 160 files from a clean checkout.
      Proof (review fix): the "any letter case" patterns were pinned only in the fixtures' cases, so `CLIP[.]EXE`,
      `The[[:space:]]+Clipboard`, `[GgSs]e[Tt]-` and `[GgSs]et-[Cc]lipboard` passed the selftest. Four new fixtures
      hold `clip.exe`, `set the clipboard to`, `SET THE CLIPBOARD TO` and `GET-CLIPBOARD`, so every letter of the
      three patterns has a fixture in each case. `--selftest` passes 346/346 under sh and dash; with the artifact
      selftest stubbed (305 passed), each of the 62 mutants that keeps one letter class to one case turns it red.
      The gate is clean on the tree.

**3. Embedded known answers, startup guards and check 12 (rules 3, 5, 8, 10 and 12; build-plan.md "Release")**
- [x] verify.py `KNOWN_ANSWERS` and `known_answers()`. Every value is a literal in the file, and a comment names its
      source by file and entry (never a `KCE/test/` label; check 12 (b)). This commit's groups:
      - hash: kat.json's SHA-256, SHA-512 and HMAC-SHA256 entries;
      - bip39: the embedded list's SHA-256 `2f5eed53…`, and one 12-word and one 24-word entry of bip39/vectors.json;
      - seed: one keepcrypt.json mixed case (D to C; D and R to E and words), and Coldcard's published `123456`
        (rolls.json: E, 12 and 24 words);
      - seal: CLAUDE.md's vector (S, code, T, Seal ID and its braille, lookup prefix, grid, colour) and the go-ahead
        vector `CF94-BCAJ`;
      - braille: the table digest `fd75c236…`, and ABANDON 0001, ACT 0020 (two blank faces), ACTION 0021, METAL 1121,
        WIRE 2018 and ZOO 2048 as their braille.json fields (number, faces, lighter face, mirror partners, cells).
      Group 4 adds `urls` and `insert`, and group 7 adds `run`. `verify.py selftest` prints one line per group and
      exits 0, or names the failing group and exits 1.
      Proof: commit 6. `python3 -I verify.py selftest` prints `ok` for hash, bip39, seed, seal and braille and exits 0
      on 3.12.5 and 3.9.6, from the tree and as check 12's read-only lone copy. Check 12 (c) rebuilds the table from
      kat.json, bip39/vectors.json english 12 and 14, keepcrypt.json `d-00-1f` and `d-00-1f-coldcard-50`, rolls.json
      `123456`, seal.json vector 1 and braille.json and finds it equal. Each group's fault twin exits 1 naming that
      group only (the changed value: hash, the HMAC-SHA256; bip39, the 24-word mnemonic; seed, dice-only word 24;
      seal, G; braille, ZOO's cells).
      Proof (review fix): one fault twin per group left the other values and the "unreadable" branch untested, and a
      copy could change the table at run time. `known_answers(table)` now takes the table. Check 12's known-answer
      sweep changes each of its 214 values in turn, which must fail that group and no other; sets each group to None,
      which must fail it alone as `unreadable`; and adds a group with no check (`no check`). Rule (c) refuses any read
      of `KNOWN_ANSWERS` but `known_answers(KNOWN_ANSWERS)`. Check 12 passes on 3.12.5 and 3.9.6. Scratch mutants of
      verify.py each fail it on both: the 11 the review lists (`unreadable` made `[]`, SHA-512 or SHA-256 only, no list
      hash, no C, no `words_12`, no Seal ID braille, no grid, no re-check URL, the last insert line only, no `no
      check`), plus G ignored, the wrong group's values and `except KeyError`. Copies that store into, `.update`,
      `del` from or alias `KNOWN_ANSWERS` fail rule (c) under `--verify-py`.
- [x] Startup guards, right after `import sys` and before any other import, when run as a script:
      - Python older than 3.9 exits 2 with one line;
      - without `-I` (`sys.flags.isolated`) it exits 2 and says to run `python3 -I verify.py ...`, so a planted module
        beside the download (for example `hashlib.py`) is never imported;
      - stdout is reconfigured to UTF-8, so braille prints the same in every locale.
      Proof: commit 6. Check 12 (d): without `-I` a copy exits 2 with `verify.py runs only in isolated mode: python3
      -I verify.py ...`, and a planted `hashlib.py` prints its marker in neither that run nor the `-I` one, which
      exits 0; the directory holds only the two files afterwards. One-off probes on both Pythons: with
      `sys.version_info` set to 3.8.18 before `runpy.run_path`, the run prints `verify.py needs Python 3.9 or later`
      and exits 2; under `LC_ALL=en_US.ISO8859-1`, stdout's encoding goes from iso8859-1 to utf-8 (group 7 (g) pins
      the braille bytes).
      Review (2026-10-10): unticked, since one-off probes are not standing proof. Check 12 (d) now runs the lone copy
      audited as Python 3.8.18 (the audit sets `sys.version_info` before the copy runs): exit 2, stderr exactly
      `verify.py needs Python 3.9 or later`, nothing on stdout. It passes on 3.12.5 and 3.9.6, and scratch copies
      whose guard is gone, checks 3.0, exits 1 or writes to stdout each fail it on both. The UTF-8 reconfigure has
      no standing test until group 7 (g)'s locale run, which ticks this item.
      Proof: commit 10. Check 12 (g) pipes the first 12-word Mixed Pi ceremony into an audited lone copy under
      `LC_ALL=en_US.ISO8859-1` (a probe shows Python's stdout there is iso8859-1 before verify.py sets UTF-8) and its
      stdout equals the UTF-8 runs' bytes, braille included; it passes on 3.12.5 and 3.9.6 on macOS, where it is
      required. A scratch copy without `sys.stdout.reconfigure(encoding="utf-8")` fails it on both (exit 70).
- [x] vectorgen check 12, "tools/verify/verify.py ships alone", with two testing-only options: `--verify-py PATH`
      (like `--vectors-dir`) and `--check N` (run one check). Every rule runs, and each failing rule is named:
      - (a) static, by `ast` over verify.py:
        - imports only from the allowlist: argparse, base64, binascii, datetime, getpass, hashlib, hmac, re, struct,
          sys, unicodedata, warnings. No `from X import *` and no `importlib`;
        - no call to or use of the names `open`, `input`, `exec`, `eval`, `compile`, `__import__`, `breakpoint`,
          `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr` or `__builtins__`;
        - no dunder attribute (`x.__class__`, `x.__dict__`, `x.__globals__`, ...). verify.py has one after the split,
          `Exception.__init__(self, error)` in `BackupRefused` (`super().__init__` would be one too), so commit 6
          makes `error` a property over `self.args[0]`, and the rule holds with no exception;
        - every attribute taken from an imported module (`hashlib.sha256`, `getpass.getpass`, `sys.stdin`) must be in a
          recorded (module, attribute) list kept in check 12, so `getpass.os`, `getpass.io`, `argparse._os` and
          `sys.modules` fail;
      - (b) the text holds neither marker (`KC_TEST_SOURCE_DO_NOT_SHIP`, `KC_TEST_REGISTRY_DO_NOT_SHIP`), no
        `KCE/test/` and not the test registry public key in hex;
      - (c) every `KNOWN_ANSWERS` value equals its source, value by value:
        - hash, bip39, seed and seal values equal their entries in kat.json, bip39/vectors.json, keepcrypt.json,
          rolls.json and seal.json;
        - each braille word equals its braille.json entry, field by field;
      - (d) lone copies:
        - a lone copy, read-only, passes `selftest` with a minimal environment;
        - for each known-answer group there is a fault twin, a lone copy with one value of that group changed. Each
          exits 1 from `selftest`, naming that group;
        - a planted `hashlib.py` that prints a marker sits beside a copy. Neither `sys.executable -I verify.py
          selftest` nor the refused run without `-I` prints it;
        - afterwards the directory holds only verify.py and the planted file;
      - (e) audit: every lone-copy run except the two planted-module runs is an audited run.
        - The harness `sys.executable -I -c <harness>` installs `sys.addaudithook`, sets `sys.argv` and runs the copy
          with `runpy.run_path(path, run_name="__main__")`.
        - The child starts with `start_new_session=True`. With no controlling terminal getpass cannot reach one, so
          local runs behave as CI's.
        - Opens: the run fails on any `open` event in a write mode. It also fails on an open of any path outside the
          interpreter's standard library directories (`sysconfig` `stdlib` and `platstdlib`) and the copy itself.
          `/dev/tty` is allowed only in group 7's terminal runs, so a getpass call on the pipe branch fails. Those
          runs also allow wrapping a descriptor already open (getpass's `io.FileIO(fd, "w+")` over /dev/tty).
        - Processes and sockets: any `socket.*`, `subprocess.Popen`, `os.system`, `os.exec`, `os.posix_spawn` or
          `os.fork` event fails the run.
        - Modules at exit: the run fails if `sys.modules` holds a module loaded from outside those directories, any
          module in group 2's network list, `subprocess` or `multiprocessing`.
      Proof: check 12 passes on 3.12 and 3.9; group 8's canaries show that rules (a) and (e) fire.
      Review fix (2026-10-10): `--verify-py PATH` replaces the subject of rules (a)-(e) only. Check 12's in-process
      parts (group 3's known-answer sweep, group 4's `INPUT_CASES` and keepcrypt.json tie) call
      `tools/verify/verify.py` as vectorgen loads it, also under `--verify-py`, since check 12 runs its subject only
      as audited copies. A changed copy's parsers meet `INPUT_CASES` in group 7's piped lone-copy runs (every refused
      text: exit 2, the field and position on stderr, no traceback, every stream under the leak rule). Since commit
      10, `--verify-py` replaces the subject of rules (a)-(g) and the command runs; the in-process parts, now with
      group 7's in-process run, still call `tools/verify/verify.py`.
      Review fix (2026-10-10, controls): disabling rule (b), rule (c)'s comparison, the fault twins, the leak test,
      the audit's `problem()` or its "end" test left `--selftest` green. Check 12 now holds its own rules to controls
      that must fire: rule (b) on each test material alone and on the test key in upper case; rule (c)'s comparison
      naming each value the known-answer sweep changes; the leak test on parsers whose refusals echo the input (the
      10 refused cases with a non-empty input); rule (d) on the fault twin of a copy that passes whatever its known
      answer; and rule (e) on two audited controls in writable directories. One opens for writing and outside the
      standard library, then tries `subprocess.Popen`, `os.system`, `os.posix_spawn`, `os.fork` and `os.exec`; each
      must be reported and refused, so it reaches its end, and `subprocess` is reported at exit. The other calls
      `os._exit` and must be reported as ending early. Neither imports socket (a banned-API gate hit in vectorgen):
      a socket needs the socket or `_socket` module, which the audit reports at exit. Proof: check 12 passes on
      3.12.5 and 3.9.6; the gate is clean. Scratch mutants of vectorgen each fail it on both: `value_differences`
      returning `[]`, rule (b) returning `[]` or matching the key's case, rule (c) skipping the insert group, the
      leak test off or ASCII-only, `problem()` returning None, the hook never raising, no "end" test, no open-outside
      branch, no `os.fork` event, banned modules unreported, no fault twins run and the twins' exit status unchecked.
      Review fix (2026-10-10, file changes): rule (e) also fails a run on any `os.truncate`, `os.remove`, `os.rename`,
      `os.rmdir`, `os.mkdir`, `os.chmod`, `os.chown`, `os.chflags`, `os.link`, `os.symlink`, `os.utime`,
      `os.setxattr`, `os.removexattr` or `shutil.*` event. Each changes a file by path with no `open` event, so a
      copy that reached `os` past rule (a) could truncate a file outside it and pass (at bb989cb: exit 0, no audit
      line, the file at 0 bytes). The refused-actions control tries the eleven found on every platform, and its
      directory must be unchanged afterwards. `os.mkfifo` and `os.mknod` raise no audit event on 3.9 or 3.12, so only
      rule (a) keeps them out of reach. Proof: check 12 passes on 3.12.5 and 3.9.6; the gate is clean. Scratch
      mutants that each drop one tried event from the list (15) fail the control on both.
      Review fix (2026-10-11, `type`): rule (a) also bans the name `type`, which reaches the class behind any object:
      `type(sys.stderr.buffer.raw)` is `io.FileIO`, which opens a file by path with no banned name, module attribute
      or dunder. verify.py never uses it. Proof: check 12 passes on 3.12.5 and 3.9.6; a copy whose exit-70 handler
      writes `verify-crash.log` that way fails rule (a) on both (`uses the name type`), as well as the audit.
      Proof: commit 11, ticked as check 13's item was, since both planned proofs are local. At 8a1b0c6 check 12
      passes on 3.12.5 and 3.9.6, and `scripts/canaries.sh` passes 61/61 under sh and dash, with verifier-import
      failing rule (a) and verifier-reach failing rules (a) and (e) as intended.

**4. Inputs, the shared run function, inserts and registry URLs (lessons.md rule 2: exact bytes of every hash input)**
- [x] Parsers. An error is `InputRefused(field, position)`, whose text never holds the input:
      - `parse_hex32(field, text)` for C and D: refuse any non-ASCII character first; remove spaces, tabs and hyphens;
        then exactly 64 hex digits in either case, giving 32 bytes (pi-firmware.md step 5: 16 groups of 4);
      - `parse_rolls(lines)`: each line is `str.strip()`ped as rolls.py:202 does. Then every character must be one of
        the ASCII digits `1`-`6`, so an internal space, `0`, `7` or a full-width digit is refused at its position. The
        lines are joined; empty input is refused. R is the joined ASCII, with no newline.
      Proof: `INPUT_CASES` in check 12, each with its expected bytes or (field, position):
      - hex: grouped, ungrouped, uppercase and hyphenated; 63 and 65 digits; `g`; an Arabic-Indic digit; empty;
      - rolls: outer spaces; a space inside; a tab inside; `0`; `7`; U+FF16; two lines joined; an empty line.
      Proof: commit 7. The 17 `INPUT_CASES` pass in check 12 on 3.12.5 and 3.9.6; each refusal's text is ASCII and
      holds no 4 consecutive characters of its input. Scratch mutants each fail their cases: inner spaces removed
      (space inside), no strip (outer spaces, `0` on a second line, two lines), `int(ch, 16)` (`g`, Arabic-Indic),
      positions counted after separators (`g`, Arabic-Indic) and a message echoing the input (4 hex refusals).
      Proof (review fix): no case pinned "non-ASCII first", since the Arabic-Indic digit alone is refused at the same
      position by the hex-digit test. An 18th case, `g` at character 3 and an Arabic-Indic digit at 11, must be
      refused at 11; a scratch copy without the non-ASCII pass gives (`D`, 3) and fails it on 3.12.5 and 3.9.6.
- [x] `verification_run(length, roll_lines, c_text=None, d_text=None)` returns one report for both modes:
      - mixed: C and D parsed, then `hmac.compare_digest(commitment(D), C)`; a mismatch stops here. The roll count must
        then lie in [50 or 99, 256] by length (verify.py `DICE`); otherwise the report says no honest device finishes
        a first ceremony with that count. Then E = `mixed_entropy(D, R)`;
      - dice-only: E = `dice_only_entropy(R)`. A count outside [50 or 99, 256] adds a warning, not a refusal (Q21);
      - seed bits and words: `bip39_words(E[0:16])` for 12 words, `bip39_words(E)` for 24;
      - the seal from the words: grouped code, T, Seal ID and its braille, lookup prefix, bucket, grid, colour index
        and hex, and the re-check URL;
      - one insert line per word (`insert_line`): position, device and device count, sequence 01-12, SeedBook number,
        word, faces 1-5 and the word's cells.
        - A face is its cell, then its letter. A mirror-pair letter adds `/<partner>`, a non-blank fifth face adds
          `~`, and a blank face is `--`.
        - Example: `01 device 1/1 seq 01 seedbook 0001 abandon | ⠁a ⠃b ⠁a ⠝n ⠙d/f~ | ⠁⠃⠁⠝⠙⠕⠝`.
      Proof (M2 Review, 2026-10-11): commit 7 (3727711); its ABANDON line equals the example. Check 13 (fcb3481,
      a3a4d4e, 9fc299f, 0d2ff75) works out every part of the report again on the 1,028 cases: the C/D refusal before
      the rolls (D with one digit changed), the mixed range and the dice-only warning against vectorgen's own quota,
      the seed bits, the words, the seal and every insert line. Core's agreement test (1f86f2c) compares every field,
      and check 12's command runs pin `render`'s text (11d1163). Scratch copies of verify.py fail check 13 on both
      Pythons, before and after a re-baseline: no C/D refusal, a 257-roll maximum, no dice-only warning, insert
      device 1, sequence = position, bucket + 1, the Seal ID braille reversed, colour index + 1, 12-word seed bits
      E[16:32], and face 0 accepted.
- [x] URL builders (Q6d; the origin stays `https://registry.invalid` until M9):
      - `recheck_url(T)` = `/check#t=<64 lowercase hex>`;
      - `check_url(T, n)` adds `&n=<16 lowercase hex>`;
      - `register_url(code)` = `/register#c=<26 uppercase, no dashes>`.
      Proof: commit 7. For seal vector 1 the three URLs equal core's pinned literals (seal.rs:456, seal/check.rs:213,
      seal/registration.rs:129) and check 12 (c)'s grammar over seal.json; a copy with the origin and its known
      answers changed together fails rule (c) on all three URLs.
- [x] Known answers, added in this commit because their functions arrive here:
      - `urls`: the re-check URL for CLAUDE.md's T, the check URL with n = `0001020304050607`, and the register URL for
        that vector's code. Check 12 (c) ties them to the grammar applied to seal.json's tag and code for the
        vector; core pins the same re-check literal at seal.rs:456;
      - `insert`: the six SeedBook words above as insert lines at position 01, device 1/1, sequence 01. Check 12 (c)
        splits each line into fields and compares them with the word's braille.json entry.
      Proof: commit 7. `verify.py selftest` prints `ok` for 7 groups on 3.12.5 and 3.9.6, from the tree and as check
      12's lone copy; the urls and insert fault twins each fail only their group. Scratch copies fail rule (c) by
      field: the register URL literal changed (`urls.register_url`), and the `~` moved to face 4 in code and answers
      alike (`insert.lines.1.lighter_face`, `.3`, `.4`). The ABANDON line equals the example above.
- [x] Check 12 gains a tie to values core already checks. It takes every keepcrypt.json `mixed` case whose D has a C
      in its `commitment` list (three of four at 90b6ab9), and every `dice_only` case. Fed as display text through
      `verification_run`, each gives the committed seed bits (`e_hex`, its first 32 hex digits for 12 words) and
      `words_12`/`words_24`. Core's seed.rs tests check those values.
      Proof: `INPUT_CASES` and this tie pass on 3.12 and 3.9. The 1,000 agreement cases (groups 5 and 6) compare every
      field with core, and check 12 pins the rendered text (group 7).
      Proof: commit 7. The tie passes on 3.12.5 and 3.9.6: 3 mixed and 6 dice-only cases at both lengths. 50 rolls
      at 24 words (`d-00-1f-coldcard-50`) is refused with no words, and `coldcard-123456` (both lengths) and
      `coldcard-50` (24 words) compute with a warning. Scratch mutants fail it: wrong 12-word seed bits, no mixed
      refusal, no dice-only warning. The agreement and the rendered text are groups 5-7's proof.
      Review (2026-10-10): unticked until that proof lands, since the item's planned proof names the 1,000 agreement
      cases (groups 5 and 6) and the rendered text (group 7).
      Proof: commit 10 lands the last part. Core compares every field of the 1,000 cases (commit 9), and check 12 pins
      the rendered text: the `run` known answers tie every stdout line of two agreement.json ceremonies to their
      expect (and to check 12's copies of the banner, commitment, roll-count and note lines), and the piped runs of
      the first ceremony of each combination print render's stdout, its expect lines equal to agreement.json's.

**5. Agreement vectors: the verifier's side (gate; build-plan.md M2 and "Verifier agreement, 1,000 cases")**
- [x] `vectorgen.py --write-agreement-vectors` writes `vectors/agreement.json`, one case per line, marked "public test
      data; never fund":
      - 1,000 ceremonies reaching Ready: 8 combinations of {12, 24} × {Mixed, DiceOnly} × {Pi, Phone}, 125 each.
        - Case 5 of each combination is a restart after a collision. A first ceremony, with its own stub, events and
          rolls, reaches Checking and is discarded as `Collision`.
        - The restart, on a fresh stub with fresh events, takes rolls drawn from [99, 256] and the Check path to Ready;
      - roll counts: cases 0-4 of each combination use the minimum, minimum + 1, 128, 255 and 256; the rest are drawn
        from [minimum, 256]. Every 8th case pushes one extra face after a drawn roll and undoes it;
      - Pi Mixed: hwrng of 1,536-4,096 bytes. The chunk plan rotates through: one chunk; 1,024 + rest;
        1,023 + 1 + rest (straddling the startup samples); eight 1-byte chunks + rest; and drawn cuts. Every stream
        passes `health_test`, or the generator stops;
      - extras: 0-4 from all four extra sources, lengths 0-64, interleaved with hwrng chunks, with at least one empty
        extra per combination. Dice-only cases get extras too, which both sides must ignore;
      - path: even cases Skip, odd cases Check. Every 5th Check case first sends a wrong G, which is stored in the
        case.
        - The wrong G's last symbol is replaced by the next Crockford value (alphabet index + 1 mod 32), in
          canonical uppercase with the dash, so core must answer exactly `WrongCode`.
        - Lowercase or an O/I/L alias would be accepted; a symbol outside the alphabet is `MalformedCode`;
      - inputs stored: the stub label and exact length (64 for Mixed, plus 8 on the check path), the events, the rolls,
        the undo step, the path, the wrong G, and for a restart the first ceremony's inputs too;
      - `expect`, from `verification_run` fed C and D as 16 groups of 4 lowercase hex:
        - C and D (null in dice-only), the seed bits, the words, the seal and the insert lines;
        - n, `check_url`, G (grouped) and `register_url`;
        - for a restart, the first ceremony's grouped code and register URL, which core's collision report must equal;
      - 28 refusal cases:
        - 24 boundary cases, 3 per combination: the minimum - 1 rolls, 257 rolls, and a face of 0 or 7 at a drawn
          position;
        - 4 restarts with 98 rolls for 12 words ({Mixed, DiceOnly} × {Pi, Phone});
        - each records core's error and step: `TooFewRolls` at `finish`, `TooManyRolls` at the 257th `push_roll`,
          `InvalidRoll` at the bad face;
        - each records the verifier's verdict: `refused` (mixed out of range, exit 1), `input-refused` (a bad face in
          either mode, exit 2), `warned` (dice-only out of range: computed with a warning), or `diverges` (the 98-roll
          restarts: the verifier cannot see a restart and computes; Q21).
      Proof: file size and generation time recorded (estimated 2-2.5 MB, about 1 s on 3.9). The generator builds each D
      with `session_records`/`device_leg`, and `verification_run` must report "C matches D". That is a
      self-consistency check only (C comes from the same `commitment`), not agreement evidence; the agreement evidence
      is group 6.
      Proof: commit 8. `python3 -I tools/verify/vectorgen.py --write-agreement-vectors` writes 1,000 ceremonies and 28
      refusals, 4,155,350 bytes in 1,048 lines (SHA-256 `da5d6682…`; 851 KB gzipped), the same bytes on 3.12.5 and
      3.9.6, generated in 1.10 s and 1.79 s. It is larger than estimated because JSON escapes each braille cell as
      `\u28xx` (6 bytes), and the insert lines are 2.2 MB of it. Expected values come from `verification_run` and the
      lines `render` prints (C, D, the words and the bucket, which render does not show, from the report); a ceremony
      that is refused, warned or not "C matches D" stops the generator. Each refusal's verdict is derived from the run
      (InputRefused, `refused`, `warning`, or computed: `diverges`).
      (changed 2026-10-11: 9a3902a reworded the spec's `expect` line to name each value's source, so the committed
      file is 4,155,498 bytes, SHA-256 `acc0770a…`, still 1,048 lines. n is the stub's last 8 bytes, and the check
      URL, G and the register URL come from verify.py's `check_url`, `go_ahead_code` and `register_url`, not from
      `verification_run`; see the SOURCES.md item's review fix.)
- [x] Check 13, "vectors/agreement.json matches regenerated output":
      - byte equality with the regenerated file;
      - coverage counts: 125 ceremonies per combination with both paths in each; every roll-count edge; at least one
        wrong first code per combination; the undo cases; every chunk plan and extra source; an empty extra; 8
        restarts; and 28 refusals (8 `refused`, 8 `input-refused`, 8 `warned`, 4 `diverges`);
      - Coldcard's hash-pinned `rolls.py` (24 words) or `rolls12.py` (12 words), run as check 4 runs them, on about 70
        cases: the dice-only refusals with valid faces and every 8th dice-only ceremony. Each must print exactly the
        case's `entropy` line and words.
      Proof: passes on 3.12 and 3.9; added time recorded (estimated 2-3 s on 3.9); group 8's tamper canary.
      Proof (commit 8; unticked until commit 11's tamper canary): check 13 passes on 3.12.5 and 3.9.6 in 3.0 s and
      5.1 s (generation 1.1 s and 1.8 s; Coldcard's scripts on 74 cases, the 64 every-8th dice-only ceremonies and the
      10 dice-only refusals with valid faces, 1.5 s and 1.9 s); the whole `--selftest` takes 9.4 s and 16.1 s (6.2 s
      and 11.0 s before). After the stage-B review (finding 7), check 13 also holds the regenerated cases to rules a
      re-baseline cannot remove: each refusal's core error and verdict against those its rolls, mode and restart call
      for; each ceremony's C, seed bits, words and seal against their definitions (`seal_vector` and the URL grammar);
      a D with one digit changed refused before the rolls are read; and every insert line against braille.json's
      positions and words. Scratch mutants each fail it on both Pythons, before and after `--write-agreement-vectors`:
      in verify.py, no C/D-mismatch refusal, a 257-roll maximum in `verification_run`'s range test, no dice-only
      warning, insert device 1, sequence = position, bucket + 1, the Seal ID braille reversed, render's colour index +
      1, 12-word seed bits E[16:32] and face 0 accepted; in vectorgen, no wrong first code, a wrong code equal to G, no
      undo, one chunk plan, no restart, a stub one byte long, no 98-roll restarts and 124 ceremonies. Dropping the
      drawn extras, or case 6, passes after a re-baseline, since either alone still gives every source and an empty
      extra.
      Proof (review fix, the quota): the coverage and refusal rules read the quota from verify.py's own `DICE`, so a
      changed `DICE` passed all 13 checks once agreement.json and keepcrypt.json were regenerated (only core caught
      it). They now read `AGREEMENT_QUOTA`, vectorgen's literals from CLAUDE.md "Dice quota" and build-plan.md's
      `push_roll`. Check 13 passes on 3.12.5 and 3.9.6. Scratch copies of verify.py with `max_rolls` 257,
      `min_rolls_12_words` 49 or `min_rolls_24_words` 98, each with both files regenerated, fail check 13 on both.
      Proof (review fix, the boundaries): the refusal rule asked only whether a count lay outside the range, so a
      generator whose cases left the boundary passed once re-baselined, and with it an off-by-one in verify.py's range.
      It now requires the 28 planned refusals, each once and at its boundary: per combination the minimum - 1 rolls,
      257 rolls, and an in-range count with one face of 0 (even combinations) or 7 (odd ones); and the four 12-word
      restarts at 98, one below core's minimum after a collision. Check 13 passes on 3.12.5 and 3.9.6. Scratch copies,
      each re-baselined, fail it on both: in vectorgen, the minimum - 2 rolls, 265 rolls, faces 8 and 9, and 97-roll
      restarts; and together with verify.py, the minimum - 2 rolls with a range that takes the minimum - 1, and 258
      rolls with one that takes 257 (both passed all 13 checks and core's agreement test before).
      Proof (review fix, controls): check 13's rules had no control, so a rule's line removed from the check with the
      matching verify.py fault passed all 13 checks: computing from a D that does not match C, or dice-only E from the
      first 256 of 257 rolls. Check 13 now holds each rule, taken from the table it runs, to a control that must fire
      (`AGREEMENT_CONTROLS`): coverage on a stub one byte longer; refusals on a changed verdict, a roll past 257 and a
      restart's first stub one byte short; seed and seal on a changed seal tag; D changed on a run that recomputes C
      from D; inserts on a line repeated in the next slot; and Coldcard's scripts on the last of 257 rolls changed.
      Check 13 passes on 3.12.5 and 3.9.6 (the whole `--selftest` in 9.4 s and 16.0 s). Scratch copies each fail it
      on both: each of the six rules returning `[]`; the D-changed or Coldcard line removed together with its
      verify.py fault; and the coverage stub test, the refusal boundary, verdict or stub test, or the seal tag
      comparison switched off.
      Proof (review fix, the case mix): the coverage rule asked only for both paths, some undo and some wrong first
      code, so a thinner mix passed once re-baselined. It now holds every case of each combination to the planned mix
      (`AGREEMENT_CASE_MIX`, literals apart from the generator's): Check on odd cases and Skip on even ones, an undo
      on cases 0, 8, 16, ... and a wrong first code on cases 9, 19, 29, ... (every 5th Check case), each held to a
      control (an even case on the check path, case 8's undo dropped, case 19's wrong code dropped). Check 13 passes
      on 3.12.5 and 3.9.6 (3.0 s and 4.9 s; the whole `--selftest` in 13.0 s and 24.1 s), and
      `--write-agreement-vectors` leaves agreement.json unchanged. Scratch copies of vectorgen, each re-baselined,
      passed check 13 before and fail it on both now: `AGREEMENT_UNDO_EVERY` 64, `AGREEMENT_WRONG_EVERY` 50 and the
      check path on every 4th case. Copies that drop each mix entry, or the whole mix test, fail its control.
      Proof: commit 11. Canaries' tamper loop changes the first digit of a rolls string from the middle of a copy of
      agreement.json on (case 24-mixed-pi-083), and `vectorgen.py --selftest --vectors-dir` fails naming check 13
      (`PASS: vectors-tamper-agreement.json failed as intended`, under sh and dash).
- [x] `vectors/SOURCES.md`: agreement.json joins "What each set is for" (generated by vectorgen.py), and `UNLISTED`
      gains it. Proof: check 3 passes.
      Proof: commit 8. SOURCES.md gains a paragraph on agreement.json (how it is generated and what check 13 checks)
      and its "What each set is for" entry; `UNLISTED` gains `agreement.json`. Check 3 passes on 3.12.5 and 3.9.6.
      Proof (review fix): the paragraph, vectorgen's docstring and AGREEMENT_* comment and the spec's `expect` entry
      said every expected value came from `verification_run` and `render`. They now name verify.py's `check_url`,
      `go_ahead_code` and `register_url`, n from the stub, and the refusals' core error and step worked out by
      vectorgen. `--write-agreement-vectors` changes only the spec's `expect` line; `--selftest` passes 13/13 on
      3.12.5 and 3.9.6, and core's agreement test passes (9 tests).

**6. Agreement: core's side (gate; rules 5, 6, 10 and 12)**
- [x] `core/tests/agreement.rs`:
      - It reads agreement.json with `common::read`. It rebuilds stub, hwrng and extra bytes with a local copy of
        no_panic.rs:23's `stream` helper (`sha2`, a core dependency).
      - One `#[test]` per combination plus one for the 28 refusals. Each asserts its case count, so libtest runs them
        in parallel and a truncated file fails.
      - Per ceremony:
        - `Session::new_with_stub(len, mode, platform, StubSource::new(StubEntropy::Fixed(os), &probe), None)`;
        - `add_hw_samples` per chunk and `add_extra`, in event order;
        - `commit`, then `commitment()` (C, or `None`);
        - `start_dice`, `push_roll` per face (and the undo), `finish`.
      - Restart: the first ceremony runs to `start_check`, then `discard(Discard::Collision)`.
        - `collision_report()`'s `url()` and `grouped_code()` must equal the first ceremony's register URL and
          grouped code.
        - Then `restart_with_stub(len, mode, <second stub>, None)`, and the restart runs as any ceremony.
      - On Sealed, `seal()` gives the case's T, Seal ID, its braille, prefix, bucket, grid, colour and re-check URL.
      - Check path:
        - `start_check`, then `check_request().url()` must equal the case's check URL;
        - the wrong G gives exactly `Rejected::Retry(_, CheckError::WrongCode)`, with the same URL afterwards;
        - `reveal(GoAhead::Code(G))` reaches Ready.
      - Skip path: `skip_check`.
      - On Ready:
        - `mnemonic().words()` equals the words, and `seal_from_mnemonic(mnemonic())` equals the seal;
        - `braille()` is collected into owned data and formatted with the insert-line grammar, then compared;
        - `check_readback` passes with every word's first four letters;
        - `registration()` gives the grouped code, register URL and Seal ID;
        - `reveal_device_leg()` gives D, or `None` in dice-only.
      - The braille formatter reads every token from core's accessors (`position`, `device`, `device_count`,
        `sequence`, `seedbook_number`, `word`, `word_cells`, and per face `is_blank`, `cell`, `letter`,
        `mirror_partner`, `is_lighter`). It keeps no local letter, partner or lighter table. For every non-blank face,
        `dots().bits()` must equal the cell's code point minus U+2800.
      - Completeness: every key of a case's `expect` object is compared exactly once. An unknown or uncompared key fails
        the case.
      - A refusal case stops with the recorded error at the recorded step.
      - Failure messages name the case and field only, never a value (`assert!(got == want, ...)`, as ceremony.rs
        does). The file has no `print*`, `dbg!`, `.ok()`, `unwrap_or*` or `let _ =`.
      Proof: commit 9. `cargo test -p keepcrypt-core --locked --features test-sources --test agreement`: 9 passed (8
      combinations of 125 ceremonies, and the 28 refusals) in 1.17 s on 16 threads, 8.47 s with `--test-threads=1`
      (debug). The seed bits are the words' SeedBook numbers as 11-bit indices. Each refusal's verifier verdict must be
      the one core's error, mode and restart call for (`input-refused` at core's roll), and each 98-roll restart's
      inputs, run as a first ceremony, give the verifier's words and seed bits. A scratch mutation script changed one
      recorded value at a time and ran that case's test: all 92 mutations fail naming exactly the case and field (C,
      D, n, the check URL, G, the wrong G equal to G or malformed, T, the Seal ID and its braille, prefix, bucket,
      grid, colour index and hex, the re-check, check and register URLs and their origin, the grouped code, the
      collision report, each of 12 words and word 24, 16 insert-line tokens, the seed bits, an extra and a missing
      key, each refusal's error, step and roll, the verdicts, the divergence's words and seed bits). A stub one byte
      short fails closed at `start_check` (and at `commit` on the skip path); a deleted ceremony or refusal fails its
      count. A scratch core whose `REGISTRY_ORIGIN` is changed fails every combination at `recheck_url`.
- [x] `core/Cargo.toml`: `[[test]] name = "agreement"`, `required-features = ["test-sources"]`, so it runs in CI
      `test` step 2 and in coverage, never in the release configuration.
      Proof:
      - `cargo test -p keepcrypt-core --locked --features test-sources --test agreement` passes all 1,028 cases, and the
        default-features run skips it. Local and CI times are recorded (estimated 7 s serial, about 2 s in parallel);
      - a one-off mutation script in a scratch copy, its output pasted under Review. One planted change per compared
        field must fail exactly that case and field. The fields are C, D, n (through the check URL), G, the wrong G
        made equal to G, T, the Seal ID, its braille, prefix, bucket, grid, colour, re-check URL, register URL, grouped
        code, collision report, each word, each insert-line token, and each refusal's error and step;
      - in the same script, a stub one byte short fails closed at `start_check`, and a deleted case fails its count;
      - group 8 adds a standing canary.
      Proof (commit 9; unticked until a CI run records its time): the default run skips it (`cargo test -p
      keepcrypt-core --locked --test agreement` stops: "requires the features: `test-sources`"; `cargo test --workspace
      --locked` passes without it). The test-sources run passes in 60.6 s, agreement 1.17 s of it, and `cargo llvm-cov
      --locked -p keepcrypt-core --features test-sources --no-cfg-coverage --fail-under-lines 95` runs it (1.22 s;
      core at 97.39% of lines). The mutation script's results are under the item above.
      Proof (M2 Review, 2026-10-11): in CI on 5100b6f (run 38115700518) the `test` job's test-sources run passes
      agreement 9/9 in 5.22 s and its default run skips it, and coverage runs it in 7.18 s (lines 97.39%); locally
      1.15 s at 5100b6f. The mutation script's output (92 changes, 0 unexpected) is pasted under Review, and the
      agreement-core canary passes in CI.

**7. The user commands: `mixed` and `dice` (design.md:239-244; mobile-apps.md:186)**
- [x] `verify.py mixed --words {12,24}` and `verify.py dice --words {12,24}`. `--words` has no default, since a 12/24
      mix-up gives 11 matching words and a wrong last one.
      - Startup: `known_answers()` runs first (groups 3 and 4), including a new `run` group. (changed 2026-10-11:
        the call is `known_answers(KNOWN_ANSWERS)` since 2db1b6f.)
        - `run` holds two cases core checks: the first 12-word Mixed Pi case and the first 24-word DiceOnly Phone case
          of agreement.json.
        - Literals: their C, D and rolls as display text, and their full rendered stdout.
        - Check 12 (c) ties each rendered line to the case's `expect`, which core compares (group 6).
      - Prompts:
        - `mixed` asks for C "as written down before the first roll" and prints it back on stderr in 16 groups of 4;
        - it then asks for D from "Reveal D", and checks C against D before it asks for the rolls;
        - rolls come in one or more lines, ended by an empty line. `dice` asks for the rolls only;
        - after each hidden entry, stderr gets only the count read ("64 hex digits", "37 rolls, 37 in all").
      - Type-ahead: each prompt drops whatever was typed or pasted before it appeared (getpass's flush), so it is never
        read. The terminal may already have shown it, since echo is on until getpass turns it off (before the first
        prompt, and between two; a paste at C's prompt arrives with echo off, so its later fields are dropped
        unseen). The guide says to wait for each prompt before typing its field. The running count makes a dropped
        line visible.
        Review fix (2026-10-11): this said a dropped type-ahead is never shown, as did the guide; a pty probe that
        wrote D before the C prompt appeared found it echoed in full on 3.12.5 and 3.9.6, then dropped.
      - End of input: before the first line at any prompt, it exits 2 with nothing computed. At the rolls prompt, after
        at least one line, it ends the list like an empty line. Pipes end this way, and Ctrl-D on a terminal does the
        same.
      - stdout, one `label: value` line each, in the device's screen order:
        - the run banner: "VERIFICATION RUN: a disposable test seed. Never fund it; erase this run and clear the
          terminal afterwards.";
        - `commitment: C matches D` (mixed); `rolls:` with the count and bits; `entropy:` the seed bits;
        - `seal-id:` with its braille, `seal-tag:`, `lookup-prefix:`, `seal-colour:`, eight `seal-grid:` rows and
          `recheck-url:`;
        - one `insert:` line per word, then `seal-code:`;
        - fixed `note:` lines. One says that for 12 words, 50-98 rolls is valid only for a first ceremony, never after
          "Match found" (Q21).
      - Exit codes:
        - 0: computed;
        - 1: a known answer failed, D does not match C, or a mixed run is outside [minimum, 256] (no words printed);
        - 2: a usage error, refused input, end of input before a first line, or a terminal that cannot hide input
          (nothing computed);
        - 70: internal error; 130: interrupted.
      - Input source:
        - a terminal that cannot hide input is refused: `getpass.GetPassWarning` is raised as an error;
        - when stdin is not a terminal, the same lines are read from stdin, after one stderr notice: "input read from a
          pipe or file: clear it from your shell history and delete any file". Tests and scripts can still drive
          every prompt.
      - No positional arguments exist. The argument parser never echoes an argument it refuses ("arguments not shown"),
        so words pasted as arguments do not reach the screen twice.
      - The docstring and `--help` are the user guide:
        - design.md's four steps, and the command `python3 -I verify.py ...`;
        - type at the prompts, never `echo ... | python3 verify.py` (Coldcard's rolls.py documents that habit, which
          leaves the rolls in shell history);
        - check the file's SHA-256 against the release notes with `shasum -a 256` or `sha256sum`. verify.py never
          prints its own hash, since a tampered copy could lie;
        - the exit codes;
        - the residual risks: Python cannot wipe memory, nothing is constant time, and terminal scrollback and swap
          remain, so use Tails and close the terminal.
        The header changes from "M1 seed" to the offline verifier. The development modes are documented in vectorgen.
      Proof: commit 10. `python3 -I verify.py selftest` prints `ok` for 8 groups (`run` added) on 3.12.5 and 3.9.6,
      and check 12's sweep, rule (c) and the `run` fault twin hold the new group like the others. Check 12's command
      runs (item below) drive every prompt, exit code and input source from lone copies; `--help` prints the module
      docstring, the guide. The rolls are a generator that `verification_run` reads only after C matches D, so the
      prompt layer adds no second computation path.
      Proof (review fix, 2026-10-11): no run pinned that `--words` has no default and takes only 12 and 24; copies
      with `default=12` or `choices=(12, 18, 24)` passed all 13 checks. Check 12's piped runs `dice` with no
      `--words` and `mixed --words 18` now must exit 2 with nothing read, giving argparse's usage line and the fixed
      refusal; both copies fail check 12 on 3.12.5 and 3.9.6.
- [x] Check 12 grows over the user commands. These are audited lone-copy runs, and every stream is held to the leak
      rule:
      - piped runs, with stdin a pipe:
        - the first case of each combination, piped as its C, D and roll lines. stdout must equal `render` of the
          in-process run, and the `entropy`, `insert`, `seal-*`, `recheck-url` and `seal-code` lines must equal
          agreement.json's `expect`;
        - `dice --words 24` and `--words 12` on `123456` print rolls.json's Coldcard words. The 12-word `entropy:` line
          is the first 32 hex digits of rolls.json's `sha256_hex`, which is what rolls12.py prints. The range warning
          and the pipe notice go to stderr;
        - one changed digit of D exits 1 with "D does not match C", with no `insert:` or `seal-` line and no rolls
          prompt;
        - a mixed run of the minimum - 1 rolls exits 1 with no words;
        - every refused text of `INPUT_CASES` exits 2, with the field and position on stderr and no `Traceback`;
        - `mixed --words 12 abandon` exits 2 without echoing `abandon`;
        - end of input before the first line at each prompt exits 2. At the rolls prompt after two lines, it computes
          with those rolls;
        - the fault twins (group 3) exit 1 from `mixed` and `dice` too, with no prompt on stderr;
      - (f) terminal runs, through `pty.fork()` (standard library, Linux and macOS, 3.9). The child is a session leader
        whose `/dev/tty` is the pty, and vectorgen waits for each prompt before typing.
        - `mixed --words 12` on the first 12-word Mixed case: C is printed back; the pty transcript passes the leak rule
          for D and the rolls; the count lines appear; the result lines equal `render`; it exits 0.
        - Paste-ahead: C, D and the rolls are written in one burst at the C prompt. Nothing of D or the rolls appears.
          The run waits at the D prompt, and typing D and the rolls normally then ends with exit 0.
        - Ctrl-D at the D prompt exits 2 with no result line.
        - `dice --words 24` with `123` and `456` on two lines, then Ctrl-D, prints Coldcard's words for `123456`.
        - In-process, with getpass made to issue `GetPassWarning`, the hidden read refuses and the command exits 2.
      - (g) locale: a piped lone run under `LC_ALL=en_US.ISO8859-1` must print braille byte-identical to the UTF-8 run.
        It is required on macOS (`verifier (python 3.9)`). On Linux it runs only where that locale is installed,
        because Python coerces the C locale to UTF-8 there.
      Proof: check 12 passes on 3.12 and 3.9. A transcript of one `mixed --words 12` run sits under Review next to
      core's values for the same case.
      Proof (commit 10; unticked until the transcript under Review): check 12 passes on 3.12.5 and 3.9.6 with 47
      audited piped runs (the 8 first ceremonies, their roll lines cut at 40; `123456` at both lengths; D changed;
      49 rolls; the 12 refused `INPUT_CASES`; `abandon`; end of input at the C, D and rolls prompts and at dice's;
      two roll lines, then end of input; 8 fault twins under `mixed` and `dice`; the locale run (g)), 5 terminal runs
      (f) (the four planned and Ctrl-C at the rolls prompt, exit 130) and 2 in-process runs (`GetPassWarning`, exit
      2; stdin closed, exit 70 with one fixed line). The paste-ahead burst carries the rolls reversed, so a run that
      read it would print other words. Check 12 alone takes 3.9 s and 8.8 s (0.8 s and 1.8 s before), the whole
      `--selftest` 12.2 s and 22.5 s (9.4 s and 16.0 s before). A new control holds the leak rule to streams that
      show D and the rolls through its normalisation, and not to near misses. Scratch mutants each fail it on both:
      in a `--verify-py` copy, the "D does not match C" text with D's hex (lower or upper case), roll lines or C read
      with echo on a terminal, argparse's own error messages, no pipe notice, the rolls read before C is checked,
      no Ctrl-C handler, no UTF-8 reconfigure, no roll counts, no C printed back, no D count, end of input after a
      roll line refused, the known answers skipped, a refusal echoing the typed C, getpass on a pipe (the audit
      refuses `/dev/tty`), the range warning on stdout, a refused run exiting 0 and refused input exiting 1; a note,
      the banner or rounded bits changed in render and the `run` literal together (rule (c) names the line); in
      tools/verify/verify.py, no `GetPassWarning` error filter, no exit-70 handler and the warning exiting 1; in
      vectorgen, the leak rule without lowercasing, with hyphens or line breaks kept, one window short, 13 rolls
      or 7 hex digits.
      (changed 2026-10-11: after the review fixes below, check 12 makes 53 audited piped runs plus one control run,
      5 terminal runs, and 1 in-process run plus 2 controls. The five argument runs join the piped runs, the
      stdin-closed run becomes an audited piped run, and the locale run gains a control. The roll lines are cut into
      the fewest lines of at most 40, as evenly as possible. Check 12 alone takes 4.1 s and 9.4 s.)
      Review fix (2026-10-11, every piped run): the fault twins' 16 runs and the locale run (g) were not held to the
      leak rule. `piped` now applies it to both streams of every piped run, so no run can leave it out, and the
      verifier-echo canaries exercise that one place. Proof: check 12 passes on 3.12.5 and 3.9.6; scratch copies
      whose known-answer refusal appends what stdin still holds, or that write D to stderr when stdin is not UTF-8,
      passed it before and fail it on both now.
      Review fix (2026-10-11, roll lines): the rolls were cut at 40 per line, so the 50 rolls of a 12-word run gave a
      last line of 10, under the leak rule's 12, and a copy that read every roll line after the first with echo
      passed rule (f). They are now cut into the fewest lines of at most 40, as evenly as possible (25 and 25; 99 as
      33, 33 and 33), so every typed line holds more than 12. Proof: check 12 passes on 3.12.5 and 3.9.6; that copy
      fails rule (f) on both, in the `mixed --words 12` and paste-ahead runs.
      Review fix (2026-10-11, whole streams): the leak rule sees only D as hex and 12 rolls in a row, and stderr and
      the pty transcript were checked only for what they must hold, so a copy that wrote `repr(report)` to stderr
      (D as raw bytes) passed check 12, as did one echoing the dice run's `456`. Each piped run's stderr, and each
      terminal run's transcript, must now be exactly what the run writes: the pipe notice, each prompt and its line
      end, C printed back, D's count, each roll count, then any warning or the line that stops the run (check 12's
      own copies of verify.py's lines), and the result lines; a refused argument gives argparse's one usage line and
      the fixed refusal. Proof: check 12 passes on 3.12.5 and 3.9.6. Scratch copies fail it on both: the
      `repr(report)` line, the roll lines after the first read with echo (now also in the dice pty run), and
      "D read" written before D is parsed (the three refused-D runs).
      Review fix (2026-10-11, typed forms): every run typed C as it is printed back and the rolls without blanks, so
      C printed back as typed, counts that include outer blanks and a line of blanks that does not end the rolls
      all passed. The mixed first ceremonies (piped) and the pty `mixed --words 12` run now type C in upper case
      without groups, the pty run's first roll line and the piped two-line run's first line carry outer blanks, and
      the piped `123456` runs end the rolls with a line of blanks. Proof: check 12 passes on 3.12.5 and 3.9.6;
      scratch copies with each of the three changes fail it on both.
      Review fix (2026-10-11, arguments): only `mixed --words 12 abandon` was refused, by the command's parser, so a
      subcommand parser that repeats its refused `--words` value (pasted rolls, say), an `@file` argument read as
      arguments (`fromfile_prefix_chars`, a file read from an argument) and `--words` with a default or an 18 all
      passed. The piped runs add `mixed --words abandon`, `dice --words` with 16 rolls, `mixed --words 18`, `dice`
      with no `--words` and `mixed --words 12 @arguments.txt`: each must exit 2 before anything is read, with
      argparse's usage line and the fixed refusal, the argument not shown and no audit line. Proof: check 12 passes
      on 3.12.5 and 3.9.6; scratch copies whose subcommand parsers are plain `argparse.ArgumentParser`, or with
      `fromfile_prefix_chars="@"`, `default=12` or `choices=(12, 18, 24)`, each fail it on both.
      Review fix (2026-10-11, exit 70): the exit-70 path ran only in process, unaudited (without `--verify-py` its
      handler ran in vectorgen itself), and only its line count was checked, so a handler that printed the
      exception's text, or wrote a file through `type(sys.stderr.buffer.raw)`, passed. An audited lone-copy run
      with stdin closed (as a shell's `<&-` leaves it) now takes that path: exit 70, stderr exactly the fixed line.
      The in-process run keeps only the `GetPassWarning` case (only a getpass changed in process warns), its stderr
      exactly its fixed line. Proof: check 12 passes on 3.12.5 and 3.9.6. Scratch copies fail it on both: the
      handler with the exception's text, or writing `verify-crash.log` (refused by the audit, which no longer runs
      unaudited), and, in a scratch tools/verify, the `GetPassWarning` refusal with a second line.
      Review fix (2026-10-11, controls): the locale run (g) and the in-process run had no control and no canary, so
      removing either from check 12 left all 13 checks and 61 canaries green. Check 12's command runs now come from
      one table (`command_parts`), and controls taken from it must fire, as check 13's do: rule (g) on the copy with
      its `sys.stdout.reconfigure` taken out (where rule (g) runs), and the in-process run on an entry that returns 0
      and on one that writes a second line. A part missing from the table fails its control. Proof: check 12 passes
      on 3.12.5 and 3.9.6. Scratch copies of vectorgen fail it on both: the locale or in-process part removed, the
      locale run returning nothing after its probe, the in-process comparison switched off, and it comparing the
      exit status alone.
      Proof (M2 Review, 2026-10-11): check 12 passes on 3.12.5 and 3.9.6 at 5100b6f. A scratch script that wraps its
      run helpers counts, on both Pythons, 54 audited runs in its command part (53 piped runs and the locale
      control), 5 terminal runs and 3 in-process calls (the run and its 2 controls), with no problem. The transcript
      of `mixed --words 12` on 12-mixed-pi-000 is under Review, beside core's agreement test for the same case.

**8. Canaries, CI and the commands of record**
- [x] `scripts/canaries.sh`:
      - the tamper loop gains `agreement.json` (9 files: the seven generated ones, agreement.json and
        age_cli_written.json), and a failing check must name it. Its comment no longer calls every file generated;
      - `agreement-core`: in the existing workspace copy (`$work/repo`), one value inside a case's `expect` is changed:
        the first hex digit of the first `"seal_tag_hex"` value from the middle of agreement.json on, found by its own
        pattern. The tamper loop's helper would change a `rolls` string there, an input core refuses as `InvalidRoll`
        before it compares any value. Then, after a `touch` of the copy's `core/tests/agreement.rs`, `cargo test
        --manifest-path "$tmp/Cargo.toml" -p keepcrypt-core --locked --features test-sources --test agreement
        --target-dir "$root/target/canary-agreement"` must fail, naming that case and `seal_tag_hex`. It has its own
        target directory, and the touch, because cargo took a copy's test binary as `Fresh` across copies that keep
        mtimes (commit 11's proof below);
      - each verifier canary runs `vectorgen.py --selftest --check 12 --verify-py <copy>` on a changed copy of
        verify.py, which check 12 must fail:
        - `verifier-import`: a copy with `import socket` fails rule (a);
        - `verifier-echo`: a copy whose C-mismatch message includes `d.hex()` fails the leak rule;
        - `verifier-echo-upper`: the same with `d.hex().upper()` fails it too;
        - `verifier-tty`: a copy that reads roll lines with `sys.stdin.readline()` on a terminal fails check 12 (f);
        - `verifier-reach`: a copy whose `selftest` opens `/dev/null` for writing through `getpass.io.open` fails,
          naming both rule (a) and rule (e);
      - `want_checks` goes from 54 to 61.
      Proof: canaries pass locally and in CI; the gates job time is recorded against the baseline.
      Proof (commit 11, local; unticked until CI runs it and records the gates job time): `sh scripts/canaries.sh`
      passes 61/61 in 160 s, and under dash in 150 s (54/54 in 117 s at a45c2d0). agreement-core builds in its own
      target directory, `target/canary-agreement` (not canary-real), and touches the copy's tests/agreement.rs
      first: in scratch trees copied with `cp -Rp` (mtimes kept, as rsync -a or git archive keep them), cargo took
      the second tree's agreement test as `Fresh` in a shared target directory, and it passed on the first tree's
      agreement.json with the second's seal tag changed; after the touch it was rebuilt and failed naming the case.
      The canary fails naming `24-mixed-pi-083: seal_tag_hex` with `test result: FAILED. 8 passed; 1 failed`, in
      3 s warm (a cold build of core's test profile took 15 s here). With core's seal tag comparison removed from
      the copy, it reports `FAIL: agreement-core passed; its gate did not fire`. The five verifier canaries take
      19 s together: verifier-import fails rule (a) (`imports socket, not on the allowlist`; rule (e) also reports
      socket loaded); verifier-echo and verifier-echo-upper fail the leak rule on the piped run with D changed;
      verifier-tty fails rule (f)'s leak test in the `mixed --words 12` and paste-ahead pty runs; verifier-reach
      fails rule (a) (`takes getpass.io, not in the recorded list`) and rule (e) (`audit: open for writing:
      '/dev/null'`).
      Proof (M2 Review, 2026-10-11): at 5100b6f canaries pass 61/61 locally (155.2 s under sh, 154.9 s under dash).
      In CI on 5100b6f the `gates` job prints PASS for agreement-core, the 9 tamper runs and the five verifier
      canaries, then `PASS: all 61 checks ran`. The job took 8m07s, its canaries step 414 s, against 3m36s for the
      whole job at the M1 baseline (run 38041799043).
- [x] `.github/workflows/entropy-ci.yml`: the selftest commands changed in group 1; the comments now name 13 checks.
      No job, step, trigger, timeout or required context changes. Proof: the diff; every job green on the M2 PR.
      Proof (commit 12, local; unticked until every job is green on the M2 PR): the selftest steps changed in commit
      3; commit 12 changes only the `gates` and `verifier (python 3.9)` comments (13 checks; the new canaries; check
      12's locale run required on macOS). The workflow parses to the same YAML before and after (`ruby -ryaml`), so
      the nine job names and every step are unchanged; `vectorgen.py --selftest` passes 13/13 on 3.12.5 and 3.9.6.
      Proof (M2 Review, 2026-10-11): `git diff a7c941e 5100b6f -- .github` changes only the two selftest steps
      (commit 3) and comments. All 14 Entropy check runs pass on 5100b6f (run 38115700518), with M1's job names.
- [x] CLAUDE.md Commands, each run as written with the output under Review:
      - `python3 -I tools/verify/vectorgen.py --selftest` (13 checks; also on `/usr/bin/python3`);
      - its eight `--write-*-vectors` (agreement added);
      - `python3 -I tools/verify/verify.py selftest | mixed --words N | dice --words N`;
      - a note that core's agreement test runs in the test-sources run.
      Proof (commit 13, local; unticked until the output is under Review): Commands gain these four, and the
      canaries line names its 61 checks. Run as written: `vectorgen.py --selftest` passes 13/13 on 3.12.5 (11.6 s)
      and 3.9.6 (22.1 s); the eight `--write-*-vectors` leave `vectors/` byte-identical (`git diff --exit-code`);
      `verify.py selftest` passes its 8 groups on both; on both, `mixed` and `dice` at `--words 12` and `24`, fed
      the first agreement.json ceremony of each kind on a pipe, exit 0 printing its recorded entropy and seal code,
      and `dice` on `123456` prints `entropy: 8d969eef...` (16 bytes for 12 words); the test-sources run passes,
      `tests/agreement.rs` 9/9; canaries pass 61/61 in 149 s.
      Proof (M2 Review, 2026-10-11): the output is under "M2: local proof": the suite at 5100b6f (every line but
      `TRYBUILD=overwrite`, which is only for a toolchain or trybuild bump, and the Pi and Android scans, which are
      CI's); the eight writers at 1b719ff (after it only check 12, the verify.py guide and this file change, and
      check 13 regenerates agreement.json byte for byte at 5100b6f); and `verify.py selftest`, `mixed --words 12`
      and `dice --words 24` as run for this record on 3.12.5 and 3.9.6.
- [x] Runtime budget, measured and pasted. If a budget is missed, stop and re-plan here.
      - `vectorgen.py --selftest` under 45 s on `/usr/bin/python3` 3.9 locally;
      - `gates` under 10 minutes: the selftest once, 9 tamper runs, 5 verifier canaries of check 12, and the
        agreement-core build and run;
      - `verifier (python 3.9)` well inside its 10 minutes;
      - `agreement.rs` under 30 s in `test`.
      Proof (M2 Review, 2026-10-11): every budget is met. `vectorgen.py --selftest` on `/usr/bin/python3` 3.9.6
      takes 23.0-23.5 s locally at 5100b6f. In CI on 5100b6f, `gates` takes 8m07s, `verifier (python 3.9)` 1m04s
      (its selftest 56 s), and agreement.rs 5.22 s in `test`.

**9. Review**
- [x] M2 Review in this file, then stop and wait for the owner's approval:
      - local proof on 3.12 and 3.9 (shell scripts also under `dash`);
      - `cargo test` in both configurations; the CI run; timings; the canary count;
      - proof per ticked item, and the gate report against build-plan.md M2.
      Proof (2026-10-11): "M2: local proof" and "M2 gate status" under Review. M3 waits for the owner's approval.

**Deferred, with their milestone** (record in their plans)
- M3, M5, M6: show D as Q19 decides, and C as 16 groups of 4 hex, the format `parse_hex32` reads. A ceremony test types
  a stub run's C, D and rolls into `verify.py mixed` and gets exit 0. M3 also takes owner item 14 (the 99-roll minimum
  lost on in-RAM wipes).
- M4: the gate's full Pi ceremony is checked with `verify.py mixed` on an offline computer, transcript under Review.
- M5, M6: core's "Verify another device" API (todo.md:822) replays `vectors/agreement.json`, the exact inputs that
  screen takes.
- M7:
  - the release form: verify.py copied byte for byte from the tag, its SHA-256 in the release notes, signed sums;
  - a release scan of verify.py reusing check 12's static and audit rules (`banned-api-check.sh --artifact` today
    covers Rust artifacts only);
  - the user guide shared by all platforms (mobile-apps.md:166);
  - a run of the lone `selftest` on the Python that current Tails ships;
  - the audit scope adding `tools/verify`. design.md asks the auditor to reproduce "a full verification run", but
    build-plan.md "Before 1.0" leaves it out.
- M9, with the pinned key and the real origin:
  - re-checks in the verifier (Q22): typed words (four-letter prefixes; non-ASCII refused before any case change) or
    an `.age` backup, then the seal, the snapshot or KCP1 lookup and the online URL;
  - a freshness rule for a computer clock (lessons.md rule 3);
  - the user path bypassing `_AGE_SCRYPT_CACHE`;
  - the scrypt choice for `/usr/bin/python3` 3.9: refuse, or a flat-table `scrypt_pure` at about 256 MiB;
  - a wallet summary with fingerprint and first address, with Jacobian secp256k1 if the time matters;
  - a terminal QR decision.
- Not planned:
  - issuing go-ahead codes;
  - BIP39 passphrase input and the watch-only export in the CLI (Python 3.9's Unicode 13.0 NFKD differs from core's
    17.0);
  - a Crockford decoder; pinned CLI transcripts in a vectors file; committed core-written `.age` files (Q24);
  - a release-configuration agreement test; the 18-word seed recompute.

### Verification
- [x] Gate, part 1 (build-plan.md M2): verifier and core agree on 1,000 generated cases, including seal codes and
      braille. `core/tests/agreement.rs` passes on the committed `vectors/agreement.json` in CI (`test` step 2 and
      coverage).
      - Compared: C, D, every word (so the seed bits), and the seal both from before the words and from
        `seal_from_mnemonic`.
      - Also compared: the check URL (T and n), G accepted and the next-value wrong G refused as exactly `WrongCode`
        with the same nonce, the register URL and grouped seal code, and every insert token read from core's
        accessors.
      - Restarts: the collision report on the 8 restarts.
      - The 28 refusal cases match their recorded verdicts. Core refuses all 28 with the recorded error at the recorded
        step. The verifier refuses the 8 mixed out-of-range cases (exit 1) and the 8 bad-face cases (exit 2). It
        computes with a warning on the 8 dice-only out-of-range cases, and computes on the 4 restarts with 98 rolls for
        12 words, a recorded known divergence (Q21).
      - Check 13 regenerates the file byte for byte on 3.12 (`gates`) and `/usr/bin/python3` 3.9
        (`verifier (python 3.9)`).
      Proof (M2 Review, 2026-10-11): in CI on 5100b6f (run 38115700518) agreement.rs passes 9/9 in the `test` job's
      test-sources run (5.22 s) and in coverage (7.18 s); `gates` and `verifier (python 3.9)` each print "ok
      vectors/agreement.json: file matches regenerated output, ..." and pass 13 checks. Locally the same at 5100b6f
      on 3.12.5 and 3.9.6. What core compares is listed under "M2 gate status".
- [x] Gate, part 2: dice-only output matches Coldcard `rolls.py`.
      - Check 13 runs `rolls.py`/`rolls12.py` on about 70 dice-only cases, including strings outside KeepCrypt's range,
        and compares each printed hash line with `entropy` exactly (16 bytes for 12 words).
      - Check 4 (rolls.json, keepcrypt.json) still passes.
      - The lone `dice` prints Coldcard's words and hash line for `123456` at both lengths, and the seed known answers
        include `123456`.
      Proof (M2 Review, 2026-10-11): at 5100b6f `vectorgen.py --selftest` passes 13/13 on 3.12.5 and 3.9.6. Check 13
      runs Coldcard's hash-pinned scripts on 74 dice-only cases (the 64 every-8th dice-only ceremonies, and the 10
      dice-only refusals with valid faces: 49, 98 and 257 rolls), and each prints exactly the case's `entropy` line
      and words; its control changes the last of 257 rolls and must fail. Check 4 passes. Check 12's piped
      `dice --words 24` and `--words 12` on `123456` print rolls.json's words, the 12-word `entropy:` line being the
      first 32 hex digits of its `sha256_hex`, and the `seed` known answers hold rolls.json `123456`.
- [x] Matrix "Verifier agreement, 1,000 cases | Verifier | Every build": both sides run in every CI run that touches
      `Entropy/` (`test`, coverage, `gates`, `verifier (python 3.9)`), and the agreement-core canary proves core's side
      fails on a changed value.
      Proof (M2 Review, 2026-10-11): on 5100b6f both sides ran in `test`, coverage, `gates` and `verifier (python
      3.9)`, and `gates` printed `PASS: agreement-core failed as intended`.
- [x] Matrix "Coldcard `rolls.py` cross-check | Core, verifier | Every build": core replays rolls.json (M1) and the
      agreement's 500 dice-only ceremonies, and check 13 ties a subset to Coldcard's own scripts.
      Proof (M2 Review, 2026-10-11): on 5100b6f tests/vectors.rs (4, rolls_json_through_dice_only_sessions among
      them) and agreement.rs's four dice-only tests pass in `test` and coverage, and check 13 runs Coldcard's
      scripts on 74 cases in `gates` and `verifier (python 3.9)`.
- [x] Matrix "Seal, braille and descriptor vectors | Core, verifier | Every build": seal and braille are compared case
      by case. Descriptors are unchanged (watchonly.json, check 9, `tests/vectors.rs`) and green after the split.
      Proof (M2 Review, 2026-10-11): on 5100b6f agreement.rs compares the seal and every insert field of the 1,000
      cases in `test` and coverage. Check 9 (watchonly.json) passes in `gates` and `verifier (python 3.9)`, and
      tests/vectors.rs passes 4/4. watchonly.json changed only in its `description` (76dd1fb).
- [x] The split changed no M1 output and left provenance true:
      - at the split commit, the seven vectorgen-written files are byte-identical, and checks 1-11 print their M1 lines;
      - after the provenance commit, only their `description` strings differ;
      - age_cli_written.json and the fetched files match their SOURCES.md hash rows;
      - no committed file names a removed `verify.py` mode or check, except the recorded age_cli_written.json sentence
        and SOURCES.md's record of it;
      - age-interop passes against Ubuntu's age 1.1.1.
      Proof (M2 Review, 2026-10-11): group 1's two items (99edb77 and 76dd1fb). At 5100b6f, `git grep -nE
      'verify\.py (--write|--selftest|check [0-9])' -- ':/' ':/!Entropy/tasks/todo.md'` finds only
      age_cli_written.json:2 and SOURCES.md:341, its record, and check 3 passes. `age-interop (age 1.1.1)` on
      5100b6f prints its three ok lines and refuses 17 of the 17 armor cases.
- [x] Deliverables:
      - `tools/verify/verify.py` with `selftest`, `mixed` and `dice` working from a lone copy (check 12);
      - "KeepCrypt vectors" = `vectors/agreement.json`;
      - "age interop files" as Q24 decides.
      Proof (M2 Review, 2026-10-11): check 12 passes at 5100b6f on both Pythons, its command runs driving `selftest`,
      `mixed` and `dice` from lone copies; agreement.json is committed (fcb3481, 9a3902a) and check 13 passes; Q24
      counts the age interop files delivered in M1 (`vectors/age/age_cli_written.json` and the `age-interop (age
      1.1.1)` job).
- [x] Release form (build-plan.md "Offline verifier | A single Python file"): a lone copy passes `python3 -I verify.py
      selftest` on 3.12 and 3.9, and a fault twin in any known-answer group refuses every command before any prompt.
      Proof (M2 Review, 2026-10-11): check 12 (d) on 3.12.5 and 3.9.6 at 5100b6f: a read-only lone copy passes
      `selftest` with an empty environment. Each of the 8 groups' fault twins exits 1 from `selftest` naming that
      group, and from `mixed` and `dice` with stderr exactly one line naming it, so no prompt appears.
- [x] Rules for the shipped file. Check 12 passes, and its canaries fail as they should.
      - Rule 1: imports only the allowlist, with module attributes from the recorded list; no Python `random`.
      - Rule 5:
        - nothing comes from arguments;
        - in the pty runs (f), D and the rolls never appear, a paste-ahead is dropped, and only counts are printed;
        - in piped runs, no input is echoed in errors, no traceback is printed, and the pipe notice is shown.
      - Rule 8: no `open` in the source, and no file opened outside the standard library in any audited run.
      - Rule 10: no marker, test key or `KCE/test/` label.
      Proof (M2 Review, 2026-10-11): check 12 passes on 3.12.5 and 3.9.6 at 5100b6f, and canaries pass 61/61 under sh
      and dash, with verifier-import (rule (a)), verifier-echo and verifier-echo-upper (the leak rule), verifier-tty
      (rule (f)) and verifier-reach (rules (a) and (e)) failing as intended. Since a5543a6 every roll line typed for
      an agreement.json case holds more than the leak rule's 12 rolls. Since ae5c3c5 each piped run's stderr and each
      pty transcript is pinned whole, so rule (f) sees every roll line, not only the first (stage D's high finding).
      The 123456 runs type shorter lines (`123456` piped; `123` and `456` in the dice pty run), which no 12-roll
      window sees; their stderr and transcript are pinned whole and their stdout must be render's, so an echo of
      them fails. The gates job of CI on 5100b6f (run 38115700518) is the first Linux run of the pty transcripts.
- [x] The banned-API gate is clean, with Q23's Python patterns firing on their fixtures.
      Proof (M2 Review, 2026-10-11): at 5100b6f `banned-api-check.sh` is clean (165 files) and `--selftest` passes
      346/346, under sh and dash; every Python pattern has a hit fixture and a near miss (commits 5, 5b and the
      stage-A and stage-B fixes).
- [x] Runtime within group 8's budget; canaries pass at 61; every CI job green on the M2 PR; no new dependency, CI job
      or required context.
      Proof (M2 Review, 2026-10-11): group 8's budget item; canaries 61/61 locally and in CI; all 14 Entropy check
      runs green on 5100b6f. Since a7c941e, Cargo.lock is unchanged, core/Cargo.toml gains only the `[[test]]`
      entry, and the workflow keeps its jobs (commit 3's two selftest steps, and comments).
- [x] Definition of done (CLAUDE.md), with proof pasted under Review.
      Proof (M2 Review, 2026-10-11): tests landed with each change (the gate fixtures, checks 12 and 13,
      agreement.rs) and pass locally and in CI on 5100b6f; agreement.json is the vectors file the gate names; fmt,
      clippy, deny and the banned-API gate are clean; the proof is under Review. Each stage had plan, security and
      recompute reviews, and every high and medium finding is fixed (46 findings, listed under Review).

### New dependencies
None. verify.py and vectorgen.py stay standard library only. verify.py adds `getpass` and `warnings`. vectorgen adds
`ast`, `getpass`, `importlib.util` (group 1's load by path), `io`, `pty`, `select`, `signal` and `time`; check 12's
audit harness, which runs as a child, imports `runpy` and `sysconfig`, and its refused-actions control `shutil`.
Core's test uses `sha2` and `serde_json`, both already approved.

### Commit order on `m2-verifier`
1. tasks/todo.md: the M2 plan, plus the owner's answers to Q16-Q24 (the title becomes "milestones M0, M1 and M2").
2. docs: the owner-approved M2 edits (Q19), alone in one commit with no code.
3. verify, scripts, ci, CLAUDE.md: split into the shipped verify.py and tools/verify/vectorgen.py as a pure move.
   The seven generated files stay byte-identical and checks 1-11 are unchanged. age-interop.py, canaries' tamper loop,
   the two CI selftest steps (now with `-I`) and Commands call vectorgen.py in the same commit.
4. verify, vectors, core: provenance names vectorgen.py: the seven `description` strings (files regenerated),
   SOURCES.md, the age_cli_written.json note (Q16 (b)), and six core comment lines (comments only).
5. scripts: Python networking and clipboard patterns in the banned-API gate, with selftest fixtures (Q23).
   5b. scripts: the stage-A review (F10) completes the gate's Python clipboard and network lists, within Q23.
6. verify: startup guards, the known answers (hash, bip39, seed, seal, braille) and `verify.py selftest`. vectorgen
   gets check 12 (static allowlist, no test material, known answers equal their sources, lone copy and fault twins,
   audited runs) plus `--verify-py` and `--check`.
7. verify: input parsers, `verification_run`, `render`, `insert_line` and the registry URL builders, with the `urls`
   and `insert` known answers. `INPUT_CASES` and the keepcrypt.json tie join check 12.
8. verify, vectors: `--write-agreement-vectors`, vectors/agreement.json, check 13 (coverage counts, Coldcard subset),
   SOURCES.md and `UNLISTED`.
9. tests: core/tests/agreement.rs replays agreement.json under test-sources, with its `[[test]]` entry.
10. verify: the `mixed` and `dice` commands, the `run` known answers, the pipe notice, the quiet argument parser and the
    docstring guide. Check 12 adds the user-command runs, piped and in a pty, and the locale case.
11. scripts: the agreement.json tamper canary, agreement-core, verifier-import, verifier-echo, verifier-echo-upper,
    verifier-tty and verifier-reach; the pinned count goes from 54 to 61.
12. ci: job comments name 13 checks.
13. CLAUDE.md: Commands for M2.
14. tasks/todo.md: M2 Review with pasted proof and the gate report.

## M3: Pi app on simulator (`pi/app`, `pi/sim`)

### Inputs from M2 (folded into the plan below)

**Starting point**
- `m3-pi-sim` is at 8e6917b: main's merge 156c8ef plus the M2 approval note in this file.
- Rules are cited from the clone's `Entropy/CLAUDE.md`.
- The gate (build-plan.md:293): "Every screen including seal check with go-ahead code entry and braille pages, button
  handling, waiting-screen game, USB export and snapshot import mocked". Its proof: "Scripted run drives a full
  ceremony in the simulator; you review the screen captures".
- M4 (:294) adds the drivers, the hwrng reader, Buildroot and real USB export.

**Scaffolds**
- `pi/app` (`keepcrypt-pi`, lib and bin) is `src/lib.rs` (one doc line) and `src/main.rs` (`fn main() {}`). It depends
  only on keepcrypt-core.
- `pi/sim` (`keepcrypt-pi-sim`, bin) is `fn main() {}`. It depends only on keepcrypt-pi and has no `[lints]` table.
- Cargo.lock holds no display, QR or GPIO crate.

**Gates that bind pi/app**
- `pi/app/Cargo.toml:13-32` forbids `unused_must_use`, `disallowed_methods`, `let_underscore_must_use`, `print_stdout`,
  `print_stderr` and `dbg_macro`. canaries.sh pins that table.
- `pi/app/clippy.toml` equals core's. It bans:
  - `unwrap_or*`, `map_or*`, `.ok()`, `.err()` and `or`/`or_else`, on Result and Option;
  - `mem::forget` and `catch_unwind`;
  - stdout and stderr.
- The real-crate canaries append to `pi/app/src/lib.rs` and run clippy on its lib 8 times (canaries.sh:127-246).
- FailOpen covers pi/app but not pi/sim (banned-api-check.sh:101, :561). Rule1 and the RNG category scan pi/sim too.
- Rule1's `#![forbid(unsafe_code)]` check reads only `core/src/lib.rs` (banned-api-check.sh:567).
- The selftest builds each fixture tree with `fresh()`, which writes only `core/src/lib.rs` (:580). Each fixture
  holds exactly one file and must give exactly one hit or none. Fixtures are dispatched by name prefix (`rng-`,
  `network-`, `clipboard-`, `rule1-`, `failopen-`, `include-`, `clean-`), and every category needs a fixture (:718-721).
  `rule1-lib-rs-absent` expects exactly one Rule1 hit on an empty directory.
- No gate sees std's OS-seeded hashing (`HashMap`/`HashSet` with `RandomState`). Core uses `HashSet` once, in a test
  (core/src/pool.rs:67).

**Manifest constraints found while planning**
- canaries.sh:700-705 appends a `[dev-dependencies]` table to a copy of `pi/app/Cargo.toml`. A real table there would
  make that copy invalid TOML, and the canary would fail. So pi/app takes no dev-dependency in M3, and tests that need
  vectors live in pi/sim.
- canaries.sh:707-712 appends a `[target.'cfg(unix)'.dependencies]` table naming keepcrypt-core to a copy of
  `pi/sim/Cargo.toml`. A normal keepcrypt-core edge in pi/sim's `[dependencies]` is a different table, so that copy stays
  valid and the pin still fires.
- The manifest pin reads only `features` lists (canaries.sh:626-637), so `required-features` never trips it. It also
  pins the root `[profile]` exactly (:600-604): the workspace crates stay at opt-level 0 in test builds.
- `cargo run -p keepcrypt-pi-sim --features keepcrypt-core/test-registry` fails today ("does not contain this
  feature"). A direct edge to core with no features fixes it (probe in `scratchpad/m3-plan/featprobe/`).
- serde_json 1.0.151 is exempted safe-to-run only (supply-chain/config.toml:242-244), so it can only be a
  dev-dependency. sha2 0.11.0 (:246) and zeroize 1.9.0 (:314) are safe-to-deploy.

**Core drives every screen, with no new API on the main path**
- Boot: `self_test`, `hwrng_boot_test` (exactly 1,024 samples), `registry_key_is_test`.
- `Session::new(len, mode, Platform::Pi)` (session.rs:169), which reruns the full KAT suite. Its doc (and
  `Wiped::restart`'s, wiped.rs:120) says "An `Err` means no seed can be made."
- Step 4:
  - `add_hw_samples`;
  - `add_extra`, which returns nothing, cannot fail and does nothing in dice-only mode (session.rs:232);
  - `hw_bytes_tested` and `HW_BYTES_NEEDED` (1,536, source.rs:40);
  - `credited_bits` (0, then 2,048 at the first window) and `required_bits` (512 on the Pi).
- Commitment and dice: `commit`, `commitment() -> Option<[u8; 32]>`, `start_dice`, `push_roll`, `undo_roll`, `rolls`,
  `millibits`, `minimum_rolls`, `finish`.
- Check: `seal()`, `skip_check`, `start_check`, `check_request().url()`, `reveal(GoAhead::{Snapshot, Code})`,
  `Rejected::{Retry, Collision}`, `discard(Discard::{Collision, CannotCheck})`, `Wiped::{collision_report, restart}`.
- `Ready`:
  - `mnemonic` and `braille`;
  - `check_readback` (3 or 4 letters, never wipes) and `readback_complete`;
  - `fingerprint` and `first_address`;
  - `generate_backup_passphrase(self) -> (Self, NewBackupPassphrase)` (session.rs:419), `encrypt_backup` and
    `verify_backup` (never wipes);
  - `watch_only` (its `qr_text()` is already uppercase for alphanumeric mode), `registration` and `reveal_device_leg`.
- Outside a session:
  - `verify_snapshot`, read with `number`, `date`, `entry_count` and `lookup`;
  - `decrypt_backup`, read with `fingerprint`, `seal`, `recheck_url`, `reveal_words` and `reveal_braille`.
- Which calls wipe:
  - An `Err` from any method that takes `self` has already wiped the session.
  - Only `Rejected::Retry`, `check_readback` and `verify_backup` keep it alive (session.rs:10-34).
  - A snapshot `reveal` never gives Retry (inner.rs:266-282).
- Five shell-order mistakes wipe by design:
  - `commit` below the quota;
  - `add_hw_samples` in dice-only mode;
  - a 257th roll, or a face outside 1-6;
  - `finish` below the minimum;
  - an export before the read-back, or `encrypt_backup` before `generate_backup_passphrase`.
- `CoreError` display text is fixed and holds no secret, for example `NoRegistryKey` is "no registry key is pinned in
  this build" (error.rs:137) and `Health` is "{test} in the {stage} stage at sample {sample}". The error enums are not
  `#[non_exhaustive]`.
- What a `Wiped` holds: the platform, the 99-roll flag and, after a collision, a `CollisionReport`. The report carries
  the destroyed seed's seal code and is wiped on drop (core/src/seal/registration.rs:69-72). A `Wiped` holds no seed or key.
- The compile-fail fixture `wiped_holds_no_secret.stderr:49-53` quotes rustc's hint with the line
  `pub fn restart(self, len: SeedLength, mode: Mode) -> ...` and its underline.

**What core lacks**
- The game-randomness call (build-plan.md:91, :207-211).
- A restart that survives the idle wipe, for item 14: today it is `Wiped::restart(self, ..)` (wiped.rs:121).
- Backup-passphrase entry that suits a joystick: `from_words` takes exact list words (secret.rs:309).
- A QR encoder: core returns payload strings only.
- `go_ahead_code` and the Crockford alphabet are crate-private (seal.rs:49, crockford.rs:14). release_probe.rs:112
  already recomputes G with sha2.

**Public vectors usable without a new file**
- keepcrypt.json `health` (byte counts measured):
  - `counting-1536` (1,536 bytes, i mod 256; passes, 512 credited);
  - `run-of-6-startup` (2,048 bytes; RCT, startup, sample 505);
  - `apt-62-startup` (2,048 bytes; APT, startup, sample 500);
  - `run-of-6-continuous` (2,048 bytes; RCT, continuous, sample 1505);
  - `stuck` (16 bytes) and `alternating` (512 bytes) are shorter than the boot test's 1,024 samples, so the simulator
    does not use them.
- keepcrypt.json `dice_only`:
  - `coldcard-50`, byte-equal to kcr.json `dice-50-words12` (Seal ID YVM9CPP3);
  - `coldcard-99`, byte-equal to `dice-99-words12` (9FHYMCQA; "various tape mercy east hair tragic arrest together
    day tag afford occur");
  - also `dice-99-words24` (RXDANDFR).
- keepcrypt.json `commitment` `d-00-1f`: a public D (bytes 00..1f) with its C.
- kcr.json snapshots:
  - `with-dice-50`: No. 4, dated 20260301, 7 entries; holds dice-50 only;
  - `with-vector-1` and `small`;
  - the refusals (`flipped-signature-r`, `bad-magic`, ...).
- backup.json `age_files` `abandon-12` and `zoo-24` (work factor 10), with their passphrases.

**CI**
- Nine jobs, 14 required check runs.
- `test` runs `cargo test --workspace --locked` and `-p keepcrypt-core --features test-sources`. It took 2m58s
  (todo.md:5249).
- `cross` runs clippy on `keepcrypt-core keepcrypt-pi` for `arm-unknown-linux-gnueabihf`, and builds and scans only
  core's release rlib and `release_probe` (entropy-ci.yml:481-501). todo.md:982 expects M3-M6 to add their own
  artifacts to the scan.
- `gates` took 8m07s of its 10 minutes, of which the canaries step was 414 s (todo.md:3446, :5311).
- `coverage` is core only.

**Carried into M3**
- The game call (todo.md:629-633).
- Restarts only through `Wiped::restart`, with tests for "99 after Stop" and "99 after a Cannot check in the restart
  after a collision" (:634-635, :2293-2296).
- `Platform::Pi` asserted in a pi/app test (:2297).
- Test-registry builds only via `-p`, and their scan shows "registry marker, no stub marker" (:2298-2299).
- The date confirmed before `reveal` (:2300-2301).
- The step 4 bar on `hw_bytes_tested` (:2302).
- C and D as 16 groups of 4 hex, and the verify.py tie (:3490-3492).
- Owner items 13 and 14 (:451-461).
- The banned-API routes (:5314-5317).
- The wait-for-prompt caveat for verify.py (:5321, explained at :5226): guidance text only.
- The `gates` budget (:5311).
- verify.py prints in the device's screen order (:3260-3268).

**lessons.md**
1. Computed numbers come from committed scripts.
2. State the exact bytes of every hash input.
3. The Pi has no clock, so it shows a date and asks the user to confirm it.

**CODEOWNERS** covers pi/app, core, every Cargo.toml, Cargo.lock, scripts, .github, docs, supply-chain and CLAUDE.md.
It does not cover pi/sim.

### Plan

**References and terms**
- Docs are named by file (build-plan.md, design.md, pi-firmware.md, mobile-apps.md, and seal-watchonly-braille.md as
  swb, all in `docs/`), plus CLAUDE.md, lessons.md and this file.
  - Line numbers into `docs/` in this M3 section, its inputs included, are the docs' after commit 2 (c306bc2),
    which added lines to build-plan.md and pi-firmware.md; Q25-Q34 keep the numbers they were asked with.
- Q25-Q34 are this milestone's questions, under "Needed before M3 code".
- Symbols are as in CLAUDE.md: D, C, R, E, S, T, n, G.
- "Step N" is pi-firmware.md "User flow" step N (1-15).
- A "screen" is one `ScreenId`, with a stable kebab-case name, a class (Public or Protected, Q29), a key map, and a
  kind: input-waiting, or transient (shown while the app works, never while it waits for a key).
- The "screen model" (`Screen`) is what a frame shows, as data: screen id, strips, body elements (text, word, braille
  cells, seal grid, QR payload, hex groups, Snake board) and soft-key labels. Secret values are separate `Protected`
  elements.
- A "vector run" is a dice-only run on a keepcrypt.json roll string, so its words and seal equal kcr.json's.
- A "throwaway run" is a Mixed run: D comes from the real OS, and the seed is never used anywhere but the screen.
- The "kept Wiped" is the `Wiped` the app holds until a check passes or the user skips (Q26).
- A "halt" is the terminal red `halt` screen (Q25): no key leaves it; only a power cycle does.
- The "release config" is `cargo test --workspace` (no registry key). The "registry config" is
  `cargo test -p keepcrypt-pi-sim --features keepcrypt-core/test-registry`.

Groups land in the order below. Core comes before the shell that calls it, the screen model before the HAL that
carries it, and every commit names a proof that runs at that commit.

**Built into this plan (override any of them)**
- **Scope is the gate:**
  - every screen of steps 1-15 and of Home's side flows;
  - button handling and Snake;
  - mocked USB export and snapshot import;
  - all driven by scripted runs in the simulator, with captures for the owner.
  - Hardware, the image and the measurements are M4.
- **One app, two hardware layers.**
  - pi/app holds everything that ships: the HAL traits, the screen model, `Frame`, input, ceremony, screens, the
    renderer, QR, Snake and the USB flows.
  - pi/sim implements the HAL, drives the scenarios and writes PNGs. pi/app never depends on it.
  - `pi/app/src/main.rs` stays a stub until M4 wires the device HAL.
- **One owner of the session and of every secret** (pi-firmware.md:66).
  - A private `Stage` enum holds the only `Session<S>` and every secret value the shell holds, inside the variant
    that needs it: the `NewBackupPassphrase` and its `ConfirmChallenge`, the entry-grid buffer, the
    `Bip39Passphrase`, the `CheckedBackup`, and the `.age` bytes read for a check.
  - Each transition moves the session out (`mem::replace`), so only the typestate's own methods can be called.
  - `Idle` and `Halted` are unit variants. One `wipe()` replaces the whole `Stage`, zeroizes the frame and presents a
    black frame; the idle wipe, a halt and Finish all call it.
  - The current-screen state (id, page, cursor) holds no secret, but where an entry grid's cursor rests, which the
    Protected grid shows (after a press, on the symbol just typed); a refused entry emptied on its own screen puts it
    back on the first symbol (review fix, 12g). `App::holds_secrets()` says whether any `Stage` data is held (the
    idle warning and the idle wipe use it).
- **One drawing path.** Screens only build `Screen` models. `ui::render(&Screen)` is the only code that draws.
  `Frame::new` is visible only inside `ui`, so every `Frame` belongs to a `ui::Painter` (outside `ui`'s own tests) and
  no other module can draw (compiler-enforced). pi/sim makes Painters of its own (the placeholder, its tests), outside
  the device path. Each present hands the HAL the frame and the model it was drawn from.
- **The app redraws only after an event changed its state** (a dead key draws nothing). The frame is cleared before
  each render and zeroized after each present.
- **Layout.** A 12 px top strip (step title, or the TEST REGISTRY and SIMULATOR banners, which take precedence) and a
  12 px soft-key footer leave a 240×216 content area. `Screen::fits()` computes every element's box from font metrics.
- **The shell never makes a wiping call by mistake.**
  - Each action core would refuse is offered only when a pure gate function says yes: Continue below the quota, Done
    below the minimum, a 257th roll, steps 10-15 before the read-back, and encrypt before generate.
  - Each gate function has a unit test. Core's wipe stays the backstop, and reaching it halts (Q25).
- **Where new sessions come from.**
  - From the kept `Wiped` while there is one (`restart`), otherwise `Session::new(.., Platform::Pi)`.
  - `Session::new` appears once in pi/app (a Shell grep, group 13).
  - Each newer `Wiped` (from a `discard`) replaces the kept one. The kept `Wiped` is dropped at `Ready` (Skip or a
    passed check) and by a halt. The idle wipe keeps it.
- **Fail closed** (rule 3; Q25).
  - These halt: every `Err` that ended a session; every `Kat`, `Source`, `Health`, `Internal` or `ExportSelfCheck`
    error from any call (`game_random` included); every Display, Buttons or HwRng fault.
  - These return to their own screen, and nothing else does: a wrong go-ahead code (`Retry`), a read-back mismatch, a
    wrong backup passphrase or unrecognised entry, an empty BIP39 passphrase, snapshot refusals (including
    `NoRegistryKey`), and USB faults.
  - No retry of a halted call, no other source.
  - Refusal screens show core's fixed text for the error, verbatim.
- **Secrets** (rule 5).
  - Typed letters, backup words and the BIP39 passphrase sit in `Zeroizing` buffers inside the `Stage`. D's hex is
    formatted into a `Zeroizing<String>` only while its model is built.
  - `Screen<'a>` borrows session text; it owns no secret copy except those `Zeroizing` buffers.
  - The frame and the QR buffers are wiped after use and on every wipe.
  - Types that hold secret text have no `Debug` or `Clone`.
  - pi/app prints nothing. pi/sim prints only screen ids, scenario names, counts and render times.
  - pi/sim's assertions compare secret text with `assert!` and fixed messages, never `assert_eq!` (as in
    core/tests/ceremony.rs:13-16).
- **Files** (rule 8).
  - pi/app touches files only through `hal::Usb`. It lists and reads only `.age` (up to 8 KiB) and `.kcr` names,
    under a read-only mount.
  - It writes only a core `BackupFile`, and never over an existing name. Only the file just written can be removed.
  - The simulated stick lives in RAM. pi/sim reads no file from disk, and writes only PNGs and an index (Q30).
- **Test data is public and repeatable**: vectors read by pi/sim's tests through `include_str!` and serde_json, roll
  strings, and the counting stream. Never a PRNG.
- **Key presses** are debounced and nothing more. pi-firmware.md defines no type-ahead filter, and the plan adds none.
  The wait-for-prompt caveat is guidance text for verify.py (step 14 and pi-firmware.md step 14).
- **No threads in M3** (Q33 (k)). No new CI job and no required-check change.
- **Out of M3:** see "Deferred, with their milestone".

**0. Before code**
- [ ] Record the owner's answers to Q25-Q34, quoted with the date.
      Answers recorded 2026-10-11 under "Needed before M3 code" ("approve all").
  - Apply the approved doc edits (Q34) alone in commit 2, with no code.
  - CLAUDE.md edits go in their own commits.

  Proof: the answers in this file; `git diff --name-only` of commit 2 lists only `docs/`.
- [ ] Baseline at 8e6917b, pasted under Review and used by group 14's budgets:
  - `cargo test` in both configurations, with counts and times;
  - canaries 61/61, with wall time;
  - `vectorgen.py --selftest` 13/13;
  - the `test` and `gates` job times from the last main run.

  Proof: pasted under "M3: local proof".

**1. Core: `game_random` (Q27; rules 1, 3; build-plan.md:91, :207-211)**
- [x] `pub fn game_random(buf: &mut [u8]) -> Result<(), CoreError>` in `core/src/source.rs`.
  - The body is one `Source::Os.fill(buf)` (source.rs:132).
  - Re-exported next to `ExtraSource` (lib.rs:61).
  - Its doc comment says: for games only; never for dice, D, nonces, passphrases or any pool input; takes no session
    and touches no pool; plain bytes; the real OS in every build; an error halts the device.
  - Tests, next to `os_source_fills_and_two_reads_differ` and `os_source_writes_every_byte_position` (source.rs:267,
    :285):
    - two 32-byte reads differ;
    - every position of a 64-byte buffer is written over 16 reads;
    - an empty buffer is `Ok`.

  Proof: `cargo test -p keepcrypt-core` in both configurations; `git diff core/src/lib.rs` adds one name; coverage
  stays at 95% or more.
  Proof (commit 3): `game_random_fills_and_two_reads_differ` and `game_random_writes_every_byte_position` pass in
  `cargo test --workspace --locked` (core's unit tests: 163 passed) and with `--features test-sources` (191 passed);
  `git diff core/src/lib.rs` adds only `game_random` to the `source` re-export; `cargo llvm-cov` 97.40% of core's
  lines (source.rs 98.71%), over the 95% floor.
- [ ] `core/examples/release_probe.rs` calls `game_random` and exits with its own code on failure, so every cross leg's
  scan covers the new draw site.

  Proof: the six cross scans are clean on the PR, and each still finds only its target's OS import. The call itself
  is proved by review alone (recompute review of commits 3-6): no gate fails without it, since the probe links the
  OS import through the session's draws anyway, and each leg's scanned rlib holds `game_random`'s code either way
  (`game_random` is a defined symbol of the host's release rlib). Exit code 20 is reached by no test.

**2. Core: the borrowing restart (owner item 14; Q26 (C); rule 6). Replaced by (A) if the owner picks it.**
- [x] `Wiped::restart(&self, len, mode)` and `restart_with_stub(&self, ..)`.
  - `Wiped` still holds only the platform, the flag and the report, and stays non-`Clone`.
  - The module docs at session.rs:10-15 and wiped.rs:9-18 say that a restart borrows, that an `Err` from it leaves the
    `Wiped`, and that the report's seal code lives as long as the `Wiped`.
  - New tests in `core/tests/check_flow.rs` (test-sources):
    - two restarts from one collision `Wiped` both need 99 rolls, for 12 and for 24 words;
    - a Cannot check inside the restart after a collision gives a `Wiped` whose restarts are at 99;
    - a Cannot check in a first session gives 50, twice.
  - `core/tests/compile_fail/wiped_holds_no_secret.stderr` is regenerated (`TRYBUILD=overwrite`). Its diff touches
    only the quoted `restart` signature line and its underline. Every other fixture is unchanged.

  Proof: check_flow and typestate output; the `.stderr` diff pasted; coverage.
  Proof (commit 4): `cargo test -p keepcrypt-core --locked --features test-sources`: check_flow 9 passed (the three new
  tests: `a_kept_wiped_restarts_at_99_until_a_check_passes`, which also shows a failed restart leaving the `Wiped` and
  its report, `a_cannot_check_in_the_restart_after_a_collision_restarts_at_99` and
  `a_cannot_check_in_a_first_session_restarts_at_50`), typestate 1 passed (all 23 fixtures), core unit tests 191
  passed; `cargo test --workspace --locked`: typestate 1 passed, core unit tests 163 passed. After
  `TRYBUILD=overwrite cargo test -p keepcrypt-core --locked --test typestate`, `git diff --stat core/tests/compile_fail/`
  lists only `wiped_holds_no_secret.stderr`, 2 insertions and 2 deletions: the quoted line
  `pub fn restart(self, len: SeedLength, mode: Mode) -> ...` became `pub fn restart(&self, ...`, and its underline
  grew by one `^`. `cargo llvm-cov` 97.40% of core's lines (session/wiped.rs 100%), over the 95% floor.
  Proof (review fix, commit 4b): `the_shipped_restart_keeps_a_kept_wiped_at_99` calls the shipped `restart` (the OS
  source, as the Pi does) twice on one collision `Wiped`, for 12 and 24 words: 99 rolls both times, and the report
  stays. `cargo test -p keepcrypt-core --locked --features test-sources`: check_flow 10 passed. Two scratch mutants
  that change only the shipped body (the 99-roll flag used once; the report gone after a restart) passed check_flow
  before this test and fail it now.

**3. Core: `TypedBackupPassphrase::from_first_four` (Q32 (b))**
- [x] `from_first_four(words: &[&str]) -> Result<Self, CoreError>`.
  - Exactly 8 entries, each the first four lowercase letters of a list word, or a whole three-letter word.
  - Anything else is `Backup(PassphraseWords)`, before any scrypt run.
  - Same zeroizing type as `from_words`. No word list leaves core (`word_list` stays private, secret.rs:27).
  - Tests:
    - all 2,048 words round-trip from their first four letters, or the whole word for three-letter words;
    - each backup.json passphrase resolves from its first fours;
    - refused: a 4-letter entry that is no word's prefix, a 3-letter non-word, uppercase, and 7 or 9 entries;
    - `decrypt_backup` opens backup.json's `abandon-12` through it.

  Proof: test output; coverage.
  Proof (commit 5): `typed_backup_passphrase_takes_every_word_from_its_first_four` (256 groups of 8, 103 of them
  three-letter words), `typed_backup_passphrase_refuses_anything_but_eight_first_fours` (also a whole longer word,
  spaces, a digit and non-ASCII) and `first_fours_give_every_backup_json_passphrase` (the passphrases of all 60
  entries in `passphrases`, `age_files` and `age_refused` agree with `from_words`, except CCTV's "password" in 2
  files, refused by both; `decrypt_backup` opens `abandon-12`) pass in `cargo test --workspace --locked` (core's unit
  tests: 166 passed) and with `--features test-sources` (194 passed; no_panic's `typed_backup_words` now sweeps
  `from_first_four` too); `word_with_key` becomes `pub(crate)`, and `word_list` stays private; `cargo llvm-cov`
  97.38% of core's lines (secret.rs 97.97%, every line of `from_first_four` covered), over the 95% floor.

**4. Dependencies and manifests (Q28; rule 11)**
- [x] Manifests:
  - pi/app `[dependencies]`: `embedded-graphics = "0.8.2"`, `qrcodegen-no-heap = "1.8.1"` (a caret spec, as in the
    rest of the workspace: it excludes the yanked 1.8.0, and Cargo.lock and cargo vet pin 1.8.1), and `zeroize` with
    core's spec. No dev-dependency table (canaries.sh:700-705).
  - pi/sim: `keepcrypt-core.workspace = true` (no features) in `[dependencies]`; `sha2` and `serde_json`, at the locked
    versions, in `[dev-dependencies]`; a `[lints]` table denying `print_stdout`, `print_stderr` and `dbg_macro`.
  - `cargo update -p autocfg --precise 1.5.0`.
- [x] Cargo.lock and supply chain:
  - Cargo.lock gains exactly the 9 crates under "New dependencies".
  - getrandom's only dependent stays keepcrypt-core.
  - supply-chain gains 6 safe-to-deploy exemptions: embedded-graphics, embedded-graphics-core, az, float-cmp,
    micromath, qrcodegen-no-heap. The qrcodegen-no-heap note records that 1.8.0 was yanked the day 1.8.1 came out.
  - imports.lock gains the byteorder, num-traits and autocfg audits: one plain `cargo vet`, then `--locked`.

  Proof:
  - the lockfile diff's package names, equal to the probe's (`lockprobe/m3pin-noheap/Cargo.lock`);
  - `cargo tree -e normal,build -p keepcrypt-pi`;
  - `cargo deny --locked check`, `cargo audit`, `cargo vet --locked` and `scripts/check-path-deps.sh` clean;
  - canaries 61/61;
  - `cargo build -p keepcrypt-pi-sim --features keepcrypt-core/test-registry` resolves.
  Proof (commit 7): `cargo update --offline --workspace` locked the 9 crates with autocfg at 1.5.1, and
  `cargo update --offline -p autocfg --precise 1.5.0` held it. The lockfile diff adds exactly autocfg 1.5.0, az
  1.2.1, byteorder 1.5.0, embedded-graphics 0.8.2, embedded-graphics-core 0.4.1, float-cmp 0.9.0, micromath 2.1.0,
  num-traits 0.2.19 and qrcodegen-no-heap 1.8.1 (names, versions, checksums and edges equal to the probe's) and the
  members' new edges, nothing else. `cargo tree -e normal,build -p keepcrypt-pi` lists embedded-graphics,
  keepcrypt-core, qrcodegen-no-heap and zeroize, and below embedded-graphics only the other 7 crates;
  `cargo tree --workspace --all-features --target all -e all -i getrandom` reaches keepcrypt-core alone. One unlocked
  `cargo vet --no-minimize-exemptions` (so the refresh could not prune an existing exemption) added only the
  bytecode-alliance num-traits 0.2.19, google autocfg 1.4.0 and byteorder 1.5.0, and zcash autocfg 1.4.0 -> 1.5.0
  audits; then `cargo vet --locked`: "17 fully audited, 82 exempted" (was 14 and 76). `cargo deny --locked check`
  ok (only the old hex-conservative and syn duplicate warnings), `cargo audit` clean (103 crates),
  `scripts/check-path-deps.sh` clean (99 packages, was 90), canaries 61/61. `cargo build --locked -p
  keepcrypt-pi-sim --features keepcrypt-core/test-registry` builds with core's test-registry alone; at a9e13bf it
  fails ("does not contain this feature: keepcrypt-core/test-registry").

**5. pi/app foundations (pi-firmware.md:58-76; rules 3, 5)**
- [x] `#![forbid(unsafe_code)]` in `pi/app/src/lib.rs` and `main.rs`.

  Proof (commit 8): both files hold the line; in a scratch copy, an `unsafe` block appended to each in turn fails
  `cargo check -p keepcrypt-pi` with "usage of an `unsafe` block", pointing at that file's `#![forbid(unsafe_code)]`.
- [x] `screen.rs`, the screen model:
  - `ScreenId` with `ALL`, `class()` (Public or Protected) and `kind()` (input-waiting or transient), both static
    tables;
  - `KeyMap` per id: each key's action label, or none;
  - `Screen<'a>` (id, strips, elements, footer) and `Element`, with the `Protected` element kinds;
  - `Screen::fits()`.

  Proof: unit tests: `ALL` has no duplicate name; every id has a class, a kind and a key map; transient ids have an
  empty key map; a model with an element past the 240×216 content area does not fit.
  Proof (commit 8): `cargo test --workspace --locked`: keepcrypt-pi's 26 unit tests pass, 10 of them in `screen`:
  `ALL` holds group 8's 62 ids with unique kebab-case names equal to their variants'; the Protected set is exactly
  Q29's 14; the transient ids are boot, wait and blank, each with an empty key map, and halt and power-off are the
  only input-waiting ids with none; element boxes from the 10×20 and 6×10 metrics (wrapping included); a model fits
  only with every box inside 240×216 (one pixel past the bottom, the right or the top edge does not) and a title of
  at most 40 strip characters.
  Proof (review fix, commit 8c): `every_key_map_is_pinned` pins all 62 ids' labels key by key, so a key map changes
  only with this table; the test that checks the dice, words and every-key maps is renamed
  `the_dice_and_words_key_maps_follow_the_buttons_table`, and `KeyMap`'s doc names the one difference from
  pi-firmware.md's "Buttons" table (no KEY1 "back" on the QR and info pages, for the owner to decide). The
  recompute review's two surviving mutants (home with `MENU_BACK`, seal-qr with `PAGE`) now fail it.
- [x] `hal.rs`: the four traits the docs name, plus a clock, bundled as `Hal`.
  - `Display::present(&mut self, frame: &Frame, screen: &Screen<'_>) -> Result<(), HalError>`. The device ignores
    `screen`.
  - `Buttons::next_event(&mut self, deadline_ns: u64) -> Result<Event, HalError>`, where `Event` is
    `Key { key, at_ns }` or `Tick { now_ns }`.
  - `Clock::now_ns()`, on the same monotonic base as the key timestamps.
  - `HwRng::read_block(&mut self, &mut [u8; 64]) -> Result<(), HalError>`: exactly 64 bytes or an error.
  - `Usb`:
    - `stick()`;
    - `list(FileKind::{Age, Kcr})` and `read(&FileName, max) -> Zeroizing<Vec<u8>>`, each under a read-only mount;
    - `write_backup(&BackupFile) -> Result<Written, HalError>`: create-new (an existing name is an error), sync,
      unmount;
    - `read_written(&Written, max)` (read-only remount) and `remove_written(Written)`: only the file just written can
      be read back or removed.
  - `build_info()`: version, rootfs hash prefix, simulator flag.
  - `HalError` has fixed variants and fixed text.
  - `FileName` accepts only Q33 (g)'s names.

  Proof: unit tests refusing `../x.age`, `x.AGE.txt`, a 65-character name and `x.txt`; every `HalError` displays fixed
  text.
  Proof (commit 8): `hal`'s 4 unit tests pass: those four names and nine more are refused, a 64-character name and
  any-case extensions are accepted; each of the 15 `HalError` variants displays its pinned text; exactly Display,
  Buttons and HwRng halt (Q25).
  Proof (review fix, commit 10b): `Written::new` is public (pi/sim must make one), so the type cannot hold the rule:
  the `Usb` docs now make it each implementation's duty, M4's driver included, to keep its own record of its last
  successful write, clear it at the start of every `write_backup` and on removal, and refuse any other `Written`
  (`NotWritten`). The stick clears its record first in every write attempt; `stick`'s
  `a_later_write_attempt_leaves_no_earlier_file_readable_or_removable` (a write, sync or `Exists` failure after an
  earlier write, then a `Written` minted for the earlier file: read-back and removal are `NotWritten`, the file stays)
  passes, and fails with the clearing line removed (the review's probe: the earlier file was read back and removable).
  tests/hal.rs's stick test checks `Exists` after the removal, with a second write, since the refused attempt now
  leaves that file `NotWritten`.
- [x] `frame.rs`: `Frame` is a boxed 240×240 `Rgb565` buffer.
  - It implements embedded-graphics `DrawTarget` with `Error = Infallible`. Draws are matched exhaustively: no `.ok()`,
    no `let _`, no `_name` binding.
  - `clear()`, and zeroize after each present and on drop. `Frame::new` is `pub(in crate::ui)`.

  Proof: unit tests (a pixel reads back, off-screen pixels are clipped, `clear()` zeroes all of them); clippy and the
  FailOpen grep are clean.
  Proof (commit 8): the module is `pi/app/src/ui/frame.rs`, since `pub(in crate::ui)` needs `ui` to be an ancestor;
  `Frame::new` carries a `cfg_attr(not(test), expect(dead_code))` until group 6's `Painter` calls it. Its 3 unit
  tests pass (a pixel reads back row by row, six off-panel points and a square half off two edges are clipped,
  `clear` leaves every raw value 0); both clippy commands are clean, and `scripts/banned-api-check.sh` is clean
  (170 files). The wipe after each present is the `Painter`'s call (groups 6 and 8); drop wipes through
  `ZeroizeOnDrop`.
- [x] `input.rs`:
  - `Key`: Up, Down, Left, Right, Press, Key1-3.
  - A pure `Debouncer`: raw edges with nanosecond timestamps in, one event per press after 20 ms stable, keeping the
    first edge's timestamp. M4's GPIO driver reuses it, and SimHal runs every scripted press through it.
  - `Idle`, on `now_ns`: cover at 30 s on Protected screens, warning at 540 s while secrets are held, wipe at 600 s
    while they are held or on a Protected screen (collision-qr holds nothing in the `Stage`). Any key resets it.

  Proof: unit tests at 19.999 ms and 20 ms, bounce trains, independent keys and kept timestamps; idle thresholds on
  injected times.
  Proof (commit 8): `input`'s 9 unit tests pass: no event at 19.999 ms, one at 20 ms with the first edge's time and
  no repeat while held; a bounce train is one event; a release shorter than 20 ms and a glitch give none; two keys
  keep their own timestamps and come out in the order they settled, also when a release arrives before any poll;
  every key debounces; `Idle` steps at 30 s (Protected only), 540 s and 600 s (only while secrets are held), and a
  key resets it.
  Proof (review fix, commit 8b): the 600 s wipe also comes on a Protected screen with nothing held, so collision-qr
  (the kept `Wiped`'s seal code, outside the `Stage`) leaves the screen at 10 minutes, as `wipes_clear_the_stage`
  expects; the warning still needs held secrets (pi-firmware.md). `idle_thresholds` pins Protected with nothing held:
  none before 30 s, the cover from 30 s to 600 s minus 1 ns, the wipe from 600 s; `cargo test --workspace --locked`:
  keepcrypt-pi's 56 unit tests pass. With the old `holds_secrets &&` condition restored, the test fails at 600 s.

**6. pi/app drawing (pi-firmware.md:67, :70; swb:84-90, :274-292)**
- [x] `ui/render.rs`: `Painter` and `render(&Screen)`: clear, the strips, each element through its painter, the footer.
  - `ui/text.rs`: embedded-graphics mono fonts (10×20 for body text, 6×10 for strips and footer); a `Scaled` target
    that draws each pixel as an n×n block, so words and codes use 10×20 at ×2 (an 8-letter word is 160 px wide); word
    wrap at 240 px.

  Proof: unit tests: wrapping at 240 px; an 8-letter word at ×2 fits; the footer shows each mapped key's label; both
  banners fit the top strip together.
  Proof (commit 9): `cargo test --workspace --locked`: keepcrypt-pi's 56 unit tests pass, 30 of them new (29 in `ui`,
  and `screen`'s test of `lines`). Wrapping: a 30-character text from x = 0 and x = 40, and a 30-letter word, draw
  exactly the lines `screen::lines` gives (the same lines `Element::bounds` measures; `fits()` and the renderer share
  them) and nothing below the measured box; small text breaks at 40 characters. ×2: "abstract" is 160×40 and fits, every
  1× pixel is a 2×2 block, and only the letters past the fourth are lighter; `Scaled` clips blocks off the panel. The
  footer: on all 62 ids, each offered key's glyph sits in exactly its label's entry, a dead key's in none, each label
  once, and the line fits 240 px (the longest, words', is exactly 240); the Dice footer is drawn centred with key names
  in the accent colour, `without(Key3)` shortens it and `halt` has none. Both banners: TEST REGISTRY and SIMULATOR each
  fill half the strip with their label centred (78 and 54 px in 120), match a reference drawing, hide the title, and one
  banner takes the whole strip. Every item kind is drawn by its painter 12 px down; `Painter::present` hands the frame
  and its model to the display and wipes the frame after a present, after a display fault and after a render error (the
  display is then not called); an empty `blank` model is an all-black frame. `Frame::new`'s `expect(dead_code)` is gone,
  since `Painter::new` calls it.
- [x] `ui/braille.rs`: a face cell drawn from a 6-bit mask (`Dots::bits()`).
  - Raised dots are filled; flat dots are rings; each dot position carries its number 1-6.
  - Blank faces are rings labelled "leave blank".
  - Face 5 is drawn lighter (`is_lighter`).
  - Mirror partners are flagged.
  - The Seal ID's braille comes from the code points of `seal_id_braille()` minus U+2800.

  Proof: all 64 masks, drawn and sampled back at the dot centres, equal the mask; each dot's number is drawn at its
  sampled label position.
  Proof (commit 9): `ui::braille`'s 7 tests: all 64 masks, plain and lighter, in a 44×70 face box, the smallest
  numbered box (`NUMBERED_PITCH`, 36×56) and a 15×24 caption box: each centre is filled exactly when its bit is set,
  and both side edges of every dot are drawn (rings); the face layout is pinned (dots 1-3 down the left column, 4-6
  down the right, diameter 11); each number 1-6 equals that digit drawn alone at its position, on its dot's row, left
  of dots 1-3 and right of dots 4-6, and caption boxes draw none; a blank face is six rings with "leave" and "blank";
  a mirror letter on face 5 is lighter and flagged "mirror". `caption_cells(render_text("5e0g7j6x"))` gives core's 15
  cells (number signs 0x3c, grade 1 indicators 0x30) and eight-dot cells or letters are `BrailleCaption`.
- [x] `ui/seal.rs`: the 8×8 grid at 192×192 on a light tile the size of the grid, filled cells in `colour_hex()`
  converted to Rgb565, every cell with a dark outline (swb:87-88), the Seal ID in 10×20 beneath.

  Proof: the 64 cell centres, sampled back, equal the grid; every cell's edge pixels are the outline colour; an empty
  cell's centre is the tile colour; the page fits.
  Proof (commit 9): `ui::seal`'s 4 tests, on swb's test-vector grid: the 64 centres are #009E73 or the tile colour as
  the grid says; every cell's 1 px edge, and nothing inside it, is the outline colour (with #F0E442, the lightest
  fill); the Seal ID is centred 2 px beneath and nothing else is drawn there; the seal-image page with the element at
  (24, 0), both banners on, fits, its box 192×214. `Item::Seal` gains `seal_id`, so the painter draws the caption,
  and its box includes it. `#RRGGBB` parses in either case; anything else is `SealColour`.
- [x] `ui/qr.rs`: qrcodegen-no-heap.
  - It encodes into two pi/app buffers of `Version::new(11).buffer_len()`, zeroized after drawing.
  - Versions 1-11 (the largest that fits 216 px at 3 px with a 4-module quiet zone), with boosted error correction.
  - The largest whole module size that fits 216 px with the quiet zone, and at least 3 px.
  - A payload that does not fit is a halt, never smaller modules (core's payloads have fixed lengths, so this is a
    bug).
  - The account QR uses core's `qr_text()` (already uppercase) in alphanumeric mode.

  Proof:
  - unit tests with each kind's payload at its fixed length fit at 3 px or more: check URL 116 bytes, register and
    report URLs 62, re-check URL 97, account UR 258 alphanumeric, the descriptor QR (both descriptors, 150 bytes each,
    a line feed between: 301 bytes, version 11 at L);
  - the drawn module centres equal the encoder's modules;
  - both buffers are zero afterwards;
  - an over-long payload errs;
  - the measured versions and module sizes are pasted.
  Proof (commit 9): `ui::qr`'s 4 tests. Measured (version, level, module px): check URL 116 bytes (6, L, 4); register
  and report URLs 62 bytes (4, M, 5); re-check URL 97 bytes (5, L, 4); account UR 258 alphanumeric characters (8, L,
  3; lowercase would need byte mode and version 10); descriptor QR 301 bytes (11, L, 3). The levels are decoded from
  the format modules, because qrcodegen-no-heap 1.8.1's `error_correction_level()` skips the 0x5412 format mask
  (it reports Quartile for that version-11 L code; pi/app never calls it). For every payload, the module centres
  equal the encoder's modules, the quiet zone is at least 4 modules and light, and nothing is drawn outside the
  216 px square. Both buffers are whole and zero after each drawing and after an error; 321 bytes fit version 11
  and 322 give `QrTooLong` with nothing drawn. Version 11 is 3 px; version 12 would need 2.
- [x] `ui/hex.rs`: 32 bytes as 16 groups of 4 lowercase hex, four groups per row, read by nibble with no `as` casts.

  Proof: round-trip through verify.py's `parse_hex32` rule (strip whitespace, 64 hex).
  Proof (commit 9): `ui::hex`'s 2 tests: `d-00-1f` formats as "0001 0203 0405 0607" and three more rows, in a buffer
  that never grew (capacity 79); all 256 byte values round-trip through `parse_hex32`'s exact rule (non-ASCII
  refused, spaces, tabs and hyphens dropped, 64 hex digits in either case) with the rows typed on one line, also in
  upper case with hyphens; a missing or extra digit, or a line feed left in, is refused.

**7. pi/sim harness (Q28 (c), Q30)**
- [x] pi/sim becomes a lib, a bin and tests, with `#![forbid(unsafe_code)]`. `SimHal` (in the lib) implements every
  trait:
  - Display keeps a log of every present since the last event: screen id, the model's text (in `Zeroizing`) and a
    copy of the frame. It checks two invariants on every present: `Protected` elements appear only on Protected ids,
    and `fits()` holds. In capture mode it also writes a PNG per present.
  - Buttons is the scenario queue. Each scripted press becomes a raw edge train with bounce, run through
    `pi_app::input::Debouncer`. A `next_event` call while the current screen is transient fails the test.
  - Clock is virtual.
  - HwRng serves one byte stream: the counting stream (i mod 256, without end), or bytes handed in by a test from the
    vectors, concatenated per read phase (boot 1,024, each Mixed session 1,536). Running out is a read fault.
  - Usb is a RAM stick with insert, remove, files and a mount mode, and these faults: write fails, sync fails,
    read-back corrupt, removed. A write while mounted read-only, a write over an existing name, and removing any file
    but the one just written are all refused.
  - Faults for Buttons and HwRng at a chosen step.
  - `build_info()` gives the crate version, rootfs prefix `sim` and the simulator flag.
  - The lib embeds `KC_SIMULATOR_DO_NOT_SHIP` as core embeds its markers (`#[used]` static, asserted in a test), in
    the HwRng and Usb code (Q31 (d)).

  Proof (pi/sim tests): each failure stream's bytes equal the vector's `samples_hex` and get core's recorded verdict;
  a write fault leaves no file; the three Usb refusals; the marker test.
  Proof (commit 10): `cargo test --workspace --locked` and `cargo test -p keepcrypt-pi-sim --locked --features
  keepcrypt-core/test-registry`: pi/sim's 31 unit tests and tests/hal.rs's 5 pass in both. Read through `SimHal`,
  `run-of-6-startup` and `apt-62-startup` equal their 2,048-byte `samples_hex`, then fault, and `hwrng_boot_test` on
  the first 1,024 gives core's RepetitionCount 505 and AdaptiveProportion 500 startup verdicts; after a counting boot,
  `run-of-6-continuous` in a Mixed Pi session gives RepetitionCount, continuous, 1505 in its 24th block, every byte the
  vector's; the counting stream's first 1,536 bytes equal `counting-1536` and pass boot and a session. With a real core
  `BackupFile` (dice-only `coldcard-50`): write and sync faults and a read-only stick leave no file, a write over an
  existing name is `Exists`, reading back or removing another file is `NotWritten` and leaves it, a corrupt read-back
  fails `verify_backup`, a pulled stick stays out, and the stick's log shows every read read-only.
  `marker_is_the_documented_string` passes, and the marker is in the rlib and in tests/hal.rs's binary. `next_event`
  on a transient screen or before any present, a Protected element on a Public id and a model that does not fit each
  fail the test. An `unsafe` block appended to lib.rs and to main.rs in turn fails `cargo check` at that file's
  `#![forbid(unsafe_code)]`. The log holds the presents since the last `SimHal::take_presents`.
  Proof (review fix, commit 10c): the stick's log showing every read read-only is the simulator's construction, not
  evidence: `hal::Usb` gives the app no mount to choose, and the stick logs `Mount::ReadOnly` for every list and read
  whatever its mount. The read-only half of rule 8 holds by the HAL's shape here; the device's read-only mounts stay
  with M4 ("Deferred": real mount ... read-only mounts). The stick's docs, a test name and tests/hal.rs's comment say
  so.
  Proof (review fix, commit 10d): capture mode's placeholder flag comes from the same match arm as the bytes it
  chose, `Captured` keeps those bytes (so it has no `Debug` or `Clone`), and the file is written from them. The
  capture test in tests/hal.rs compares them, since pi/sim reads no file back: about is its frame's PNG in both runs,
  the throwaway insert is `placeholder(WordsInsert)`'s PNG and the vector insert its frame's, and those two differ.
  The reviews' mutants (the frame written in a throwaway run, the `blank` placeholder) and a flag set false each
  fail it; before, the test compared only the flag and the file length, equal for every 240×240 PNG.
  Proof (review fix, commit 10e): `each_present_logs_an_owned_copy_of_its_model_and_frame` now gives every copied
  field more than one value and asserts it: both banners, four faces with mixed dots, blank, lighter and mirror
  flags, a seal grid with filled and empty cells and its colour, and a QR, a hex and a board element, each matched
  by kind (`Shown::Qr`, not just `text()`). The recompute review's six surviving mutants of the log copy (mirror,
  dots, grid, the QR logged as text, colour, banners) and four more (blank, lighter, the hex logged as text, an
  emptied board) each fail it.
- [x] `png.rs`: Rgb565 to 8-bit RGB; an IHDR chunk, one IDAT chunk of stored deflate blocks with Adler-32, an IEND
  chunk, and a CRC-32 per chunk. The encoder is deterministic: the same frame always gives the same bytes. The
  placeholder for a Protected frame is a grey frame naming the screen id.

  Proof:
  - CRC-32("123456789") = 0xCBF43926;
  - Adler-32("Wikipedia") = 0x11E60398;
  - a hand-checked 2×2 file matches byte for byte;
  - `python3 -I` with the standard zlib decodes a PNG back to the frame's pixels;
  - a placeholder equals its reference bytes.
  Proof (commit 10): `png`'s tests pass in both configurations: the two check values; the 2×2 file equals its bytes,
  whose CRCs and Adler-32 come from Python's zlib; `python3 -I` (zlib, stdin to stdout, no file) decodes all 65,536
  RGB565 values in a 256×256 image and a drawn seal frame back to their pixels, checking every CRC, the chunk order,
  IHDR and filter 0; the words-insert placeholder's PNG has its pinned SHA-256 (f4a6b045...). The placeholder is in
  `panel.rs`, drawn by pi/app's `Painter`, grey and white only, from the screen id alone.
- [x] Measure render time per frame and per present at opt-level 0, with a 100-frame loop, before any scenario is
  written. If a full scenario would exceed the `test` budget (group 14), stop and ask for Q31 (g)'s fallback.

  Proof: the timings pasted under Review.
  Proof (commit 10): `cargo test -p keepcrypt-pi-sim --locked --test timing -- --ignored --nocapture` on this Mac, per
  present (render alone) in µs: words-insert 2105 (1189), watch-descriptor-qr 4055 (3135), seal-image 2865 (1944),
  readback-entry 2066 (1164), dice 1850 (929), game-snake 1693 (817); a PNG encode about 14 ms (captures only). A full
  scenario of about 1,500 presents takes about 6 s even at the slowest rate, and 20,000 presents 81 s, inside the
  6-minute `test` budget with room for a slower runner: the fallback is not applied.
  Proof (review fix, commit 10f): timing.rs held the tests' one print site (Q31 (i)), so group 11's count line would
  have been a second. `report` moves to tests/report/mod.rs, which every printing test includes; timing.rs prints
  through it, the same lines as before (rerun: slowest present 4190 µs, 83 s for 20,000 presents), and the plan's
  print-site lines and pi/sim's `[lints]` comment name render times too.

**8. pi/app ceremony steps 1-7, halts, restarts, idle; the scenario driver (pi-firmware.md:75-88; swb:108-164; rules 3, 6)**
- [x] `App<H: Hal>` with `start()` (boot), `step()` (one `next_event`, then its handling) and `run()` (`step` in a loop,
  for M4's main).
  - State:
    - the private `Stage`: `Idle`, `Collecting`, `Committed`, `Rolling`, `Sealed`, `Checking`, `Ready`, `Checked`,
      `BackupCheck`, `Halted`;
    - the kept `Wiped`;
    - the plan (length, mode);
    - `Option<VerifiedSnapshot>`, outside the stage and borrowed by `GoAhead::Snapshot`;
    - the idle timer and the current screen (id, page, cursor).
  - `extras::extra_for(stage_kind, mode, event) -> Option<(ExtraSource, [u8; 8])>`, a pure function: `Some((InputTiming,
    at_ns.to_be_bytes()))` for every key in Mixed `Collecting`, whether Snake is open or not, and `None` otherwise. The
    app's one call site passes it to `add_extra`.
  - A byte source for games, `games::GAME_BYTES = keepcrypt_core::game_random`, held by the app; a `#[cfg(test)]`
    setter replaces it in pi/app's unit tests.

  Proof: pi/app unit tests on the real OS, with no vectors and a minimal fake HAL:
  - the session `new_session` builds has `platform() == Pi` and `required_bits() == 512`;
  - from a collision `Wiped` (a dice-only session on "123456"-repeated rolls, Check now, `discard(Collision)`), its
    `minimum_rolls()` is 99;
  - after that restart reaches `Ready` through Skip, the kept `Wiped` is gone and the next `new_session` gives 50;
  - `extra_for` over every stage kind, mode and key, with Snake open and closed;
  - a `game_random` error injected through the setter while Snake is open ends on `halt` with
    `holds_secrets() == false`.
  Proof (commit 13): `cargo test --workspace --locked`: keepcrypt-pi's 103 unit tests pass. The first three items are
  commit 11's tests (`new_sessions_are_the_pis`, `a_kept_collision_wiped_restarts_at_99_until_skip_drops_it`).
  `extra_for` takes no screen, so its sweep of every stage kind, mode and key stays
  `only_key_presses_in_mixed_collecting_are_forwarded`, and Snake open and closed is checked at the app's one call
  site: `every_key_in_step_4_reaches_the_pool_with_snake_open_or_closed` (closed, open, played with two steers and a
  block, then left: the stage's kind and the plan's mode it hands `extra_for` forward every key). `games::GAME_BYTES`
  is `keepcrypt_core::game_random`, held by the app; the `#[cfg(test)]` `App::set_game_bytes` replaces it.
  `a_game_byte_error_while_snake_is_open_halts_holding_nothing` plays a round to the wall, injects `Source(Os)` and
  presses play again: a black frame, then `halt` with core's text, `holds_secrets()` and `keeps_wiped()` false. In a
  scratch copy, a mutant swallowing that error fails it.
  Proof (review fix, commit 13b): `games::GameBytes` is a newtype whose field only `games` reads, so the app holds
  core's game call and hands it to Snake but cannot call it (`GameBytes::test` makes another source, in pi/app's unit
  tests only). The security review's mutants, a dice face drawn from `(self.game_bytes)(..)` in app.rs and a
  `games::GAME_BYTES(..)` call in `app/ready.rs`, compiled and passed the Shell grep; in a scratch copy each now fails
  to compile, as do the same calls through the field and through `GameBytes::test` outside the tests.
  Proof (review fix, commit 13c): that test injected the error only at play again, one of the three places the app
  draws game bytes; mutants swallowing it where "Play while you wait" opens Snake, or where a step places food after a
  bite, passed every test. `a_game_byte_error_opening_snake_halts_holding_nothing` and
  `a_game_byte_error_placing_food_after_a_bite_halts_holding_nothing` (food at (9, 6), then the failing source for the
  next block) now end on the same halt, and in a scratch copy each of the three mutants fails its test. The fake HAL
  serves a tick at the app's deadline, so the unit tests' step 4 blocks go through `step`, as the device's do.
  Proof (review fix, commit 13d): `every_key_in_step_4_reaches_the_pool_with_snake_open_or_closed` recomputed
  `extra_for` from the stage's kind and the plan's mode, so deleting the app's `add_extra` call, or skipping it while
  game-snake shows, passed every test. The app now counts, in unit-test builds only, the keys its one call site hands
  to `add_extra`, and the test presses every key, offered or not, with Snake closed, open, its round over and left,
  then Continue: each is counted once, and none on the commitment; `no_dice_only_key_reaches_the_pool` counts none on
  dice-only's notice. In a scratch copy, the call skipped on game-snake, the call removed with its count and the call
  site handing `extra_for` `Mode::Mixed` each fail; the call deleted alone leaves `source`, `bytes` and `session`
  unused, which both clippy runs refuse.
- [x] Screen inventory (`ScreenId::ALL`, the coverage target; * marks transient ids):

  | Steps | Public | Protected |
  | --- | --- | --- |
  | 1-3 | boot*, halt, home, about, length, wait* | |
  | 4-6 | hwrng, game-snake, dice-only-notice, commitment, dice | |
  | 7 | check-prompt, skip-confirm, snapshot-date, seal-image, seal-id, seal-qr, check-actions, code-entry, code-wrong, check-clear, stop-confirm, collision, cannot-check-confirm | collision-qr |
  | 8-9 | privacy-gate, device-swap, readback-done | words-insert, words-overview, readback-entry, readback-mismatch |
  | 10-11 | wallet, backup-offer, usb-insert, backup-verified, backup-failed | backup-passphrase, backup-confirm, backup-confirm-wrong |
  | 12-13 | watch-offer, bip39-ask, watch-summary, register-offer | bip39-entry, watch-account-qr, watch-descriptor-qr, register-qr |
  | 14-15 | reveal-d-offer, checklist, power-off | reveal-d |
  | Home flows | usb-pick, snapshot-loaded, snapshot-failed, backup-check-result, backup-check-recheck-qr | backup-check-entry |
  | Any | blank*, idle-warning, idle-wiped, cover | |

  The Protected set is the phones' (mobile-apps.md:111: backup passphrase, reveal-D, seal code, registration and
  watch-only QRs; the words) plus every entry grid that holds a secret. collision-qr carries the destroyed seed's seal
  code.

  KEY2 "back" (the owner's decision of 2026-10-13, group 15) adds no id: code-entry returns to check-actions with the
  same check and nonce, its typed code cleared, and backup-check-entry returns to home, dropping the backup read from
  the stick. readback-entry and bip39-entry offer no KEY2. Neither move crosses the privacy gate, which stands only
  where a Protected screen is entered from a Public one.

  Proof (commit 13): `every_screen_is_expected` passes in both configurations: the union of the `Expect` ids of the
  nine scenarios in `scenarios(config)` (each one a test of its own, which fails on an unmet `Expect`) is all 62 ids
  with the test key, and all but snapshot-loaded and snapshot-date, named in the test, without it. game-snake,
  reveal-d-offer and reveal-d were the three that no scenario expected before this commit.
- [x] Steps 1-3:
  - Step 1: `boot` (version, rootfs prefix, banners), then `self_test()`, then 16 blocks into `hwrng_boot_test`. Any
    failure is `halt`.
  - Step 2: `home` with pi-firmware.md:83's five items, and the snapshot as a status line.
  - Step 3: `length` (12 by default, "fills one KeepCrypt Hinge or Screw"), then `wait` and the new session.

  Proof: scenario `boot_stops` (below) and the first steps of every scenario at this commit.
  Proof (commit 12): Home lists New seed, Dice-only seed, Check a backup, Load registry snapshot and About; every
  gate scenario passes in both configurations from boot through Home and Length (or Home's side flows), `boot_stops`
  included, and `drill_12` (registry config) shows Home's status line "Snapshot No. 4, dated 2026-03-01" after the
  load.
- [x] Steps 4-6:
  - Step 4 (Mixed):
    - one block per Tick into `add_hw_samples`, until `hw_bytes_tested() >= HW_BYTES_NEEDED` (the sim's Tick is
      100 ms; M4 sets the device's from the measured hwrng rate);
    - the bar shows `hw_bytes_tested / HW_BYTES_NEEDED` and the credited bits;
    - "Play while you wait" opens Snake (group 10);
    - Continue appears only when `credited_bits() >= required_bits()`.
    - Dice-only shows `dice-only-notice` instead (build-plan.md:220).
  - Step 5: `commit`, then `commitment` (C through `ui/hex`, with "only verification runs need to write it down"),
    then `start_dice`.
  - Step 6: `dice`:
    - "37 / 50 rolls, 95.6 bits", from `rolls`, `minimum_rolls` and `millibits` with integer arithmetic, truncated;
    - never a roll history, and the picker goes blank after each confirm;
    - KEY1 calls `undo_roll`;
    - confirm is disabled at 256;
    - Done appears only at the minimum, then `finish`.

  Proof:
  - gate-function unit tests: Continue below the quota, Done at the minimum minus one, a 257th confirm;
  - the dice text for 1, 37, 50, 99 and 256 rolls;
  - no face value in the dice model after a confirm, and the dice frame after a confirm equals the blank-picker frame
    for that count.
  Proof (commit 11): `cargo test --workspace --locked`: keepcrypt-pi's 79 unit tests pass. `screens`' gate tests:
  Continue only at the quota (511 of 512 refused), Done at the minimum and not one below (49 of 50, 98 of 99), a
  confirm only with a face picked and never at 256 rolls (no 257th confirm), undo only with a roll to undo;
  `dice_text` gives "1 / 50 rolls, 2.5 bits", "37 / 50 rolls, 95.6 bits", "50 / 50 rolls, 129.2 bits", "99 / 99 rolls,
  255.9 bits" and "256 / 99 rolls, 661.7 bits" from core's 2,585 millibits a roll;
  `the_dice_picker_is_blank_after_each_confirm`: Up from the blank picker picks 1 and Down picks 6, both wrapping, and
  after Up three times and a confirm no element shows the 3, the line reads "1 / 50 rolls, 2.5 bits", and the frame
  equals a fresh drawing of the blank picker for one roll. The app ignores a key the shown model leaves out
  (`a_dead_key_changes_nothing_and_draws_nothing`), and in the Mixed gate scenarios the first step 4 model offers no
  key (the dead-key probe presses all 8, Continue among them). "Play while you wait" lands with Snake (group 10).
  Proof (review fix, commit 11d): unticked, since commit 11 did not prove the whole item: "Play while you wait" opens
  Snake, which lands with group 10 (commit 13), and nothing checks that `commitment` shows C (a mutant drawing the
  hex of 32 zero bytes passed every test) until commit 13's verify.py tie. The bar on `hw_bytes_tested` (a carried
  item) had no check either: `mixed_12_restarts` now asserts the first `hwrng` model's empty bar, "0 / 1536 bytes
  health-tested" and "0 / 512 bits credited", and at the quota the full bar, "1536 / 1536 bytes health-tested" and
  "2048 / 512 bits credited"; it passes in both configurations, and the recompute review's mutant (the bar on
  `credited_bits()`), in a scratch copy, fails it at the quota.
  Proof (commit 13): hwrng offers "Play while you wait" until the quota and Continue from then on (`choices`).
  `mixed_12_restarts` opens Snake from it, and the first hwrng after the game shows the full bar and Continue; the
  unit test `snake_opens_in_step_4_a_wall_ends_its_round_and_the_quota_closes_it` keeps Snake open up to the block
  that meets the quota, which closes it. C is checked by the verify.py tie, which reads it off the last `commitment`
  model (verify.py stops on a C that does not match D): in a scratch copy, the mutant drawing the hex of 32 zero
  bytes for C now fails `mixed_12_restarts` at the tie (step 209).
  Proof (review fix, commit 13h): so the first step 4 model now offers Press alone, and the dead-key probe presses
  the other 7 keys; commit 11's "presses all 8, Continue among them" predates Snake.
- [x] Step 7:
  - `check-prompt`, in swb:114's words.
  - Skip: `skip-confirm` → `skip_check`. The privacy gate then carries swb:152's note.
  - Check now → `start_check`. With a snapshot, `snapshot-date` (Q33 (a)):
    - Yes → `reveal(Snapshot)` → `check-clear` ("No collision for seal <ID> as of <date>.", swb:150) or the collision
      path;
    - No → the seal card.
  - Seal card: `seal-image`, `seal-id`, `seal-qr` (`check_request().url()`), `check-actions`.
  - `code-entry` → `reveal(Code)`. On `Retry`: `code-wrong`, then entry again, with the same nonce. On a verified code:
    `check-clear` with the code-path text (Q33 (l)).
  - Match found: `stop-confirm` → `discard(Collision)` → `collision` (swb:151's words, the security address, a
    verification run suggested) → privacy gate → `collision-qr` (`collision_report().url()`) → "Add fresh entropy".
  - Cannot check: `cannot-check-confirm` → `discard(CannotCheck)` → restart.
  - Both restarts use the kept `Wiped`, with the remembered length and mode.

  Proof: unit tests:
  - Skip appears only in `Sealed`;
  - `reveal(Snapshot)` cannot be reached before `snapshot-date`'s Yes;
  - the check URL is identical before and after a Retry, and after No.
  Also before this box is ticked (the recompute review of commits 11-12, 11f): nothing yet checks how the restarts
  are wired. Each of these mutants passes both configurations, so commit 13's scenarios add the step that fails it:
  - Cannot check in a first session discards as a collision: a Cannot check in a first 12-word session must show
    "0 / 50";
  - either restart forces 12 words: a 24-word Cannot check in a first session must show "0 / 99", and a 24-word
    restart after a collision must reach a 24-word seed (on `coldcard-99`, Seal ID RXDANDFR, not 9FHYMCQA);
  - a later collision keeps the older kept `Wiped`: a second collision's `collision-qr` must carry the newer seal's
    report.
  Proof (commit 13): the unit tests `skip_is_offered_only_in_sealed`,
  `check_now_with_a_snapshot_asks_for_its_date_first` (the only `reveal(Snapshot)` is snapshot-date's Yes) and
  `a_code_that_does_not_verify_keeps_the_check_and_its_url` pass. After No the check URL is first drawn on the seal
  card, so No's proof is that it keeps the check started at Check now: in the registry configuration `check_restarts`
  loads `with-dice-50`, rolls `coldcard-99`, answers No on snapshot-date, and the mock checker's code for the check QR
  drawn after No verifies to check-clear ("No collision for seal 9FHYMCQA, as of the date your checker showed."). The
  four restart checks are `check_restarts`', in both configurations: a Cannot check in a first 12-word session shows
  "0 / 50"; a second collision's collision-qr carries `dice-99-words12`'s report, after `dice-50-words12`'s; a 24-word
  Cannot check in a first session shows "0 / 99"; and the 24-word restart after a collision shows Seal ID RXDANDFR. In
  a scratch copy each mutant fails it: Cannot check discarding as a collision (step 32), Start again forcing 12 words
  (step 114), Add fresh entropy forcing 12 words (step 148), and a later collision keeping an older collision's kept
  `Wiped` (step 80; `drill_12` and `skip_and_idle` let it pass).
- [x] Halts, idle, cover and the privacy gate:
  - Any halt condition (above) → `wipe()` → `halt` with core's fixed text, or the HAL error's.
  - 30 s on a Protected screen → `cover`; the first press only uncovers the same screen and is not passed on.
  - 9 minutes on any screen while `holds_secrets()` → `idle-warning`; a key keeps everything.
  - 10 minutes, while `holds_secrets()` or on a Protected screen (collision-qr, whose seal code is the kept
    `Wiped`'s) → `wipe()` (the kept `Wiped` and the snapshot stay) → `idle-wiped` → Home.
  - Entering a Protected screen from a Public one passes `privacy-gate`.

  Proof: unit tests for the gate rule; scenarios `runtime_stop`, `mixed_12_restarts` (its steps 1-7 part at this
  commit) and `wipes_clear_the_stage`.
  Proof (commit 12): `only_a_protected_screen_entered_from_a_public_one_is_gated` and
  `a_protected_screen_is_entered_through_the_privacy_gate`; `runtime_stop`, `mixed_12_restarts` (steps 1-7) and the
  full `wipes_clear_the_stage` pass in both configurations; the gate also stands in front of the words, the backup
  passphrase, the BIP39 entry, the watch-only and registration QRs, insert 13 after `device-swap` and a checked
  backup's words, which the scenarios pass through; the cover's first press only uncovers insert 24 in
  `dice_24_code`.
  Proof (review fix, commit 11c): `runtime_stop` also halts on an hwrng read fault in step 4, the HAL fault that
  only the boot read had a test for. The box stays open, though commit 12's report counted it ticked: "any halt
  condition" includes a `game_random` error, whose halt lands with Snake (group 10, commit 13).
  Proof (review fix, commit 12d): a USB stick put in is input, as a key is: it restarts the idle timer, so a backup
  opened after ten idle minutes on usb-insert is not wiped in the same tick (`wipes_clear_the_stage`).
  Proof (commit 13): the `game_random` error halts with nothing held
  (`a_game_byte_error_while_snake_is_open_halts_holding_nothing`, group 8's App item).
  Proof (review fix, commit 13c): it halts at each of the three places Snake draws bytes (group 8's App item).
- [x] Scenario driver (pi/sim tests). A scenario is a list of steps, built per configuration:
  - `Expect(ScreenId)`: matched in order against the Display log since the previous step, so transient screens are
    matched too;
  - `Key`, `Dice(roll string)` (Up presses, then Press, per face), `Type(text)` (grid navigation);
  - `Wait(seconds)`, `Stick(..)`, `Fault(..)`;
  - `Code(FromCheck | Wrong)`, `Readback(FromScreen | letters)`;
  - `Assert(..)` on the screen model or the frame;
  - `PowerCycle`: a new App on a new SimHal.

  Rules:
  - A key is refused unless its `Expect` screen is showing and input-waiting.
  - On the first input-waiting showing of each screen id in a scenario, each key outside its key map is pressed once
    first, and nothing may be presented.
  - On every QR screen, the drawn modules equal the encoding of the model's payload.

  Proof: unit tests: a key before its screen fails; an unmet `Expect` fails and names the step; a dead key that
  presents a frame fails; a QR frame with one flipped module fails.
  Proof (commit 11): `pi/sim/tests/scenario/mod.rs`, in tests/gate.rs, in both configurations:
  `a_key_before_its_screen_fails` ("step 1: Press pressed on home, not on its expected screen (none)"),
  `an_unmet_expect_fails_and_names_its_step` ("step 2: expected dice, presented since the last match: []"),
  `a_dead_key_that_presents_fails` (no present passes, one fails) and `a_qr_frame_with_one_flipped_module_fails` (the
  drawn check QR matches its payload and not another; with the 4×4 pixels of module (0, 0) flipped it fails) pass. The
  steps so far are `Expect`, `Key`, `Dead`, `Dice`, `Wait`, `Fault`, `Code` (grid navigation from the first symbol,
  then Done), `Assert` and `PowerCycle`; `Stick`, `Readback` and typing other grids come with group 9's flows.
  SimHal's script now ends a trailing wait with a tick at its end (`keys`, with a test), which `hal::Buttons` allows.
  Proof (review fix, commit 11b): a deadline bug made the gate spin instead of fail. The recompute review's mutant
  (`Idle::next_ns` taking a threshold at `now`, not after it) asked for a tick at the same time again and again, and
  the clock never moved, for 37 CPU-minutes. `keys` now fails the test on the ninth tick in a row that leaves the
  clock where it is (`STALLED_TICKS`; the app takes one such tick after a key that came past its next deadline):
  `a_deadline_that_never_moves_fails_the_test` and `a_few_ticks_in_a_row_may_leave_the_clock_where_it_is` pass, and
  every gate scenario passes in both configurations. With that mutant in a scratch copy, the gate fails in 1.6 s, four
  scenarios naming "its deadline never moves".
  Proof (review fix, commit 11e): the scenarios' rule 5 checks on Public screens could not fail. The "no Protected
  element" asserts after a halt and a wipe ran on Public ids, where the panel already fails any Protected element, and
  nothing looked for secret text in Public elements: the security review's mutant (word 1 as a Public line on
  check-clear) passed both configurations, and capture mode would have written it unredacted. The driver now keeps
  every secret a Protected element shows in a run (its text, its words of three letters or more, and each line of a
  QR payload or of hex) and every Public text (`Texts`), and fails the run, naming both screens, once a Public text
  equals a secret or contains one longer than any list word, whichever is shown first; a shorter one matches only
  whole, since the copy is made of list words (no Public element of any scenario is one lowercase word, so a random
  seed's word cannot match one). On a Protected screen every word, braille, QR and hex element must be Protected. The
  two tautological asserts now check only what they can (nothing held). Every scenario passes in both
  configurations in the same 7 s, and `dice_24_code`, whose backup passphrase is random, 25 times in a row. In a
  scratch copy, the security review's mutant fails `dice_24_code` and (registry configuration) `drill_12` ("a Public
  element on check-clear shows a secret a Protected element showed on words-insert"), and the recompute review's two
  marking mutants (collision-qr's QR and the insert's word made Public) fail every scenario that shows those screens.
- [x] Mock checker (pi/sim tests, sha2): G from the `t` and `n` of the check QR's payload, after the frame check above
  shows the drawn QR encodes that payload.

  Proof: vector-1's T with n = 0001020304050607 gives `CF94-BCAJ`; kcr.json's three other G values match.
  Proof (commit 11): `the_mock_checker_gives_every_kcr_go_ahead_code`: vector-1's T with n = 0001020304050607 gives
  CF94BCAJ, and all four kcr.json seeds' `go_ahead_compact` match. The checker reads T and n only from the last
  seal-qr present, whose drawn modules the driver has already matched to its payload; `dice_24_code` and
  `mixed_12_restarts` reveal with its code.

**9. pi/app steps 8-15 and the Home side flows (pi-firmware.md:89-96, :142-155; swb:200-292)**
- [x] Step 8: `words-insert`, one insert per page:
  - the header "Insert NN · device k of m";
  - the word at ×2, with letters past the fourth drawn lighter;
  - the SeedBook number as `%04d`;
  - the five face cells with numbered dots, and face 6's sequence number.
  - KEY1 toggles `words-overview` (four words). KEY2 and KEY3 page.
  - Press on the last insert starts the read-back.
  - For 24 words, `device-swap` comes before word 13, and every insert, read-back and checklist page names its device
    (swb:282). Paging on past word 12 passes it in insert view and in the overview alike; paging back needs none,
    since every page names its device (review fix, 12e).

  Proof (commit 12): `dice_24_code` pages all 24 inserts (KEY1 overview on and off, KEY3 and KEY2 in the overview,
  `device-swap` and its gate before insert 13); the inserts' words equal kcr.json's `dice-99-words24`, insert 24 reads
  "Insert 24 · device 2 of 2", the overview "Words 01-04 · device 1 of 2", and Press on insert 24 starts the
  read-back; `drill_12` (registry config) and `check_backup` show `dice-99-words12`, ABANDON with "SeedBook 0001" and
  ZOO with "SeedBook 2048". The faces are core's `Insert::faces` drawn as numbered cells (group 6), the word at ×2
  lighter from its fifth letter.
  Proof (review fix, commit 12e): only insert view's KEY3 from insert 12 went through `device-swap`: the overview
  paged from words 09-12 to 13-16 without it, and KEY1 then showed insert 13, the swap never presented. KEY3 from
  the page holding word 12 now passes `device-swap` in either view, and its Press leads on, behind the privacy gate,
  to that view's next page (`Note::Swap`). `dice_24_code` pages the overview to words 09-12, then KEY3 shows
  `device-swap`, the gate and "Words 13-16 · device 2 of 2", and KEY2 back shows "Words 09-12 · device 1 of 2" with no
  swap, before insert view and its own swap as before. It passes in both configurations (329 steps, about 1,130
  presents, 215 dead keys); with the overview's swap taken out, in a scratch copy, it fails ("expected device-swap").
- [x] Step 9:
  - `readback-entry`: 3 or 4 letters per insert, in order. No suggestions while typing. After the entry the device
    completes it from the seed and compares (`check_readback`); a match shows the whole word, then the next insert.
  - `readback-mismatch` names each `FaceVerdict`: mirror misread, should be blank, should have a letter, or wrong
    letter with the missing and extra dots. Press re-enters that insert; KEY1 shows that insert, where Press returns
    to entry.
  - `readback-done` at `readback_complete()`.
  - The SeedBook safety rules (swb:290) are in the screen copy.

  Proof: steps 10-15 are absent from every key map before `readback_complete()` (unit test).
  Proof (commit 12): `steps_10_to_15_are_not_drawn_before_every_word_reads_back`: before the read-back, the model of
  every screen of steps 10-15 and readback-done is an `OUT_OF_ORDER` halt (`screens::after_readback`, pinned by
  `the_screens_after_the_read_back_are_steps_10_to_15_and_readback_done`), and they draw once every insert reads back.
  `dice_24_code` reads back "vari" (completed to "various"), then "tap" (should have a letter), "mirc" (mirror
  misread; KEY1 shows insert 03, where Press returns to its entry), "eask" (wrong letter: missing 2 4 5, extra 1) and
  "taga" (should be blank), each corrected; every match shows the whole word and offers only done. The SeedBook
  safety rules are on the privacy gate in front of the words. The letters grid's gates are unit-tested
  (`a_letters_entry_takes_four_faces_and_a_blank_only_fourth`).
- [x] Steps 10 and 11:
  - Step 10: `wallet` (`fingerprint` as 8 hex, `first_address`).
  - Step 11, the backup:
    1. `backup-offer` → privacy gate → `generate_backup_passphrase` (once; the passphrase and its challenge go into
       the `Ready` stage).
    2. `backup-passphrase`: two pages of 4 words, with "Backup passphrase: store apart from the USB stick."
    3. `backup-confirm`: two questions of four choices, graded against `words()`. A wrong pick → `backup-confirm-wrong`
       → the pages again, with the same questions.
    4. `usb-insert` → `wait` → `encrypt_backup(&CreatedBy::new(BackupApp::Pi, ..))` → `write_backup` →
       `read_written` → `verify_backup` → `backup-verified`.
    5. On a USB fault: `remove_written` when a file was written → `backup-failed`, with Retry (re-encrypts under the
       stored passphrase, with a new file name) or Skip.

  Proof (commit 12): `dice_24_code`: the wallet summary, Back up to USB behind the gate, the passphrase's two pages,
  a wrong pick on `backup-confirm` (the pages again, the same questions), two right picks, a write fault (the HAL's
  text, nothing on the stick), Retry, then `backup-verified`: the stick holds exactly one `.age`, and `decrypt_backup`
  with the words the pages showed gives the wallet summary's fingerprint. `drill_12` and the wipes skip step 11.
  Proof (review fix, commit 12b): the only USB fault in a scenario was the write fault, which leaves no file, so no
  test reached sub-step 5's removal, the read-back or `verify_backup`, nor the passphrase generated once: mutants
  that skipped the removal, `verify_backup`, the whole read-back, or the flag each passed both configurations.
  `dice_24_code` now returns from `usb-insert` to `backup-offer` after the confirm, where Back up goes straight to
  `usb-insert`; and after the write fault and Retry, a corrupt read-back gives `backup-failed` with core's text
  ("backup rejected: bad armor"), the stick's last three calls write, read back and remove the same `.age` name, and
  the stick is empty; then Retry writes the verified backup. It passes in both configurations (315 steps, about 1,130
  presents, 215 dead keys), and the four mutants, in a scratch copy, each fail it.
- [x] Steps 12-15:
  - Step 12:
    - `watch-offer` → `bip39-ask`.
    - No → `watch_only(None)`.
    - Yes → privacy gate → `bip39-entry` (printable ASCII, Q32 (c); `Bip39Passphrase::new`; an empty entry stays on
      the screen) → `watch_only(Some)`.
    - Then `watch-summary` (that wallet's fingerprint and first address, and "treat it as private", swb:233), then the
      privacy gate, `watch-account-qr` (`qr_text`) and `watch-descriptor-qr` (receive and change descriptors on two
      lines, swb:209).
  - Step 13: `register-offer` → privacy gate → `register-qr`, with "register once, never from a restored seed"
    (swb:158).
  - Step 14 (Mixed only): `reveal-d-offer` ("D plus the rolls recreates the seed"; "type each value into verify.py
    only after its prompt appears") → privacy gate → `reveal-d` (16 groups of 4).
  - Step 15: `checklist` (swb:280, :282) → `wipe()` → `power-off`, which accepts no key.

  Proof (review fix, commit 12h): the 100-character cap (Q32 (c)) is a model gate alone (core refuses only an empty
  passphrase), and it also keeps `Steps::typed` (sized for 100) from reallocating and leaving a copy behind, yet no
  test pinned it: a mutant raising it to 150 passed both configurations.
  `the_bip39_passphrase_stops_at_100_characters_in_its_own_buffer`: with 99 characters typed, type is offered; the
  100th is taken with the buffer's capacity unchanged; then type is offered no more and a 101st press draws nothing.
  It passes, and fails with that mutant in a scratch copy.
  Proof (review fix, commit 12i): no test could see whether a step's secret goes when its screens are left, as the
  module docs say: mutants keeping the backup passphrase's display copy after the confirm, the watch-only export after
  its QRs, the registration after register-qr, or the typed BIP39 passphrase after the export each passed both
  configurations. `leaving_a_steps_screens_drops_what_they_showed` drives a read-back dice-only ceremony through step
  11's pages and confirm, step 12 with a typed passphrase and step 13, and names what the stage holds at each screen:
  the passphrase until both answers are right, the export (and no typed text) until the descriptor QR is left, the
  registration until register-qr is left. It passes, and each of the four mutants, in a scratch copy, fails it. (The
  review's marking mutants are commit 11e's.)
  Proof (commit 13): every screen of the item is now reached. `mixed_12_restarts`, a Mixed run, skips steps 11-13 to
  reveal-d-offer (its "type each value into verify.py only after its prompt appears" asserted), shows D behind the
  privacy gate on reveal-d (16 groups of 4, read by the verify.py tie), then the checklist and power-off;
  `dice_24_code` covers steps 12 and 13, and `drill_12` their Skips.
- [x] Load registry snapshot:
  - `usb-insert` → `usb-pick` (when there is more than one `.kcr`) → `wait` → `verify_snapshot`;
  - then `snapshot-loaded` (number, date, entries) or `snapshot-failed` with core's text. In release builds that is
    `NoRegistryKey`'s "no registry key is pinned in this build".

  Proof (commit 12): `drill_12`: release config, one `.kcr`, no picker, `snapshot-failed` with "no registry key is
  pinned in this build"; registry config, `usb-pick` lists `flipped-signature-r.kcr` and
  `keepcrypt-registry-2026-03-01.kcr` (`with-dice-50`): "registry snapshot or proof rejected: bad signature", then
  "Snapshot No. 4, dated 2026-03-01, 7 entries.";
  `check_backup` (registry config) loads `with-vector-1` with no picker.
- [x] Check a backup:
  1. `usb-insert` → `usb-pick` → privacy gate.
  2. `backup-check-entry`: 8 entries, first four letters each (Q32 (b)).
  3. `wait` → `decrypt_backup`.
  4. `backup-check-result`: fingerprint and Seal ID, plus, when a snapshot is loaded, the lookup count "as of
     <date>".
  5. On request: `backup-check-recheck-qr` (`recheck_url()`, T only), or, after the privacy gate, the words in insert
     view.
  6. Done drops the `CheckedBackup` and returns Home.
  - A wrong passphrase or an unrecognised entry returns to entry with core's refusal text.

  Proof for this group: scenarios `drill_12`, `dice_24_code`, `skip_and_idle` and `check_backup` (group 11), each at
  this commit.
  Proof (commit 12, Check a backup): `check_backup` in both configurations: `usb-pick` lists `abandon-12.age` and
  `zoo-24.age`; an entry "zzzz" is refused with core's text verbatim and the screen's own line "Type the first four
  letters of each word, or a whole three-letter word." right under it (also pinned by
  `an_unrecognised_entry_shows_cores_text_with_the_first_fours_instruction_under_it`); the first fours open it to
  fingerprint 73c5da0a and Seal ID 5E0G7J6X; "Registrations: 1, as of 2026-03-01" with `with-vector-1` loaded, no
  count without; the re-check QR is `.../check#t=<vector-1's T>`; the words behind the gate; Done drops the backup;
  `zoo-24` opens to 244c267a with ZOO 2048.
  Proof (review fix, commit 12c): the only refusal typed was "zzzz", which `from_first_four` refuses before
  `decrypt_backup` runs, so a wrong passphrase (a Q25 refusal) had no test: a mutant halting on it passed both
  configurations, as did mutants dropping a USB fault from usb-pick, reading a `.age` up to the snapshot limit and
  counting a missing seal as one registration. `check_backup` now also types zoo-24's first fours against abandon-12:
  the wait screen, then `backup-check-entry` with "the passphrase does not open this backup", the entry emptied
  ("word 1 of 8") and the backup still held; then a pulled stick (`Fault::Removed`) on Check a backup shows "the USB
  stick was removed" on usb-pick, and an 8,193-byte `.age` picked there shows "the file on the USB stick is too
  large"; and zoo-24's result shows "Registrations: 0, as of 2026-03-01" with `with-vector-1` loaded (registry
  configuration; release: no count). It passes in both configurations (release: 183 steps, 523 presents; registry:
  193 steps, 530 presents), and each of the four mutants, in a scratch copy, fails it (the count's in the registry
  configuration).
  Proof (review fix, commit 12f): the words footer labelled Press "read-back" on a checked backup's last insert,
  where Press goes back to `backup-check-result`; a model could only drop keys, not rename them, so the footer did not
  name the action (Q32 (a)). `Screen::relabel` names an offered key's action where a model's differs (a dead key stays
  dead), and the checked backup's last insert labels Press "done". The test
  `the_dice_and_words_key_maps_follow_the_buttons_table` pins `relabel`, `every_key_map_is_pinned`'s comment names
  this one model, `check_backup` asserts "done" there and `dice_24_code` "read-back" on the ceremony's insert 24.
  Both pass in both configurations; without the relabel, in a scratch copy, `check_backup` fails.
  Proof (review fix, commit 12g): the `View` doc and this plan said the current-screen state holds no secret, but an
  entry grid's cursor rests on the symbol just typed, and a refused backup passphrase, emptied on
  `backup-check-entry`, left it on its last letter. The refusal now puts the cursor back on the first symbol, and the
  doc and the plan's line say where the cursor may rest. The unit test of an unrecognised entry starts with the
  cursor on the last letter typed and asserts it on 'a' after the refusal; it passes, and fails without the reset.

**10. pi/app Snake (Q27; pi-firmware.md:132-138; rule 1)**
- [x] `games/snake.rs` and `games/mod.rs`:
  - an 18×18 grid of 12 px cells (216 px); one cell per Tick; the joystick steers and KEY1 leaves;
  - a wall or self hit ends the round, and the screen stays `game-snake` ("Round over · Press to play again") until
    the quota closes the game;
  - food is placed by rejection sampling over free cells, from the app's game byte source; `games/mod.rs` is the only
    place in pi/app that names `game_random`;
  - reachable only from `hwrng` (Mixed, Collecting); it closes itself at the quota;
  - the game returns a board model and holds no session and no sink; the app's loop forwards its presses (group 8).

  Proof:
  - unit tests with fixed bytes: 10,000 placements stay on free cells; the snake grows on food; a wall ends the round
    and the id stays `game-snake`; rejection skips out-of-range bytes;
  - group 8's injected-error test;
  - group 13's Shell grep;
  - scenario `mixed_12_restarts`.
  Proof (commit 13; the box stays open for group 13's Shell grep, commit 15): `games::snake`'s 8 unit tests pass:
  10,000 placements on boards of 1 to 320 snake cells, each offered every cell from a cell of its own, as accepted
  byte values between skipped bytes, land on the first free cell offered (a counting stream would not do: its pairs
  of consecutive bytes reach only a few cells); 252 and 255 are skipped and 251 is 17; a taken cell is drawn again;
  a full board gets no food and ends the round; the snake grows on food and new food is placed; a wall ends the
  round with the board unchanged, and nothing moves after; the body ends it, but the cell the tail leaves does not;
  a steer into the neck is ignored; a source error is passed on. In the app, the round over stays on game-snake,
  titled "Round over · Press to play again" with only play-again and leave offered
  (`snake_opens_in_step_4_a_wall_ends_its_round_and_the_quota_closes_it`); group 8's injected-error test passes, and
  so does `mixed_12_restarts`. By hand until the gate lands: only `games/mod.rs` names `game_random` in pi/app, and
  `pi/app/src/games/` names none of the Shell tokens.
  Proof (commit 15): group 13's Shell grep is clean on the tree and fails on the `shell-games-*` fixtures (each Shell
  word, also in `games.rs`) and on `game_random` in `pi/app/src/app.rs`. The grep allows the name anywhere under
  `pi/app/src/games/`; that `games/mod.rs` alone names it today rests on review (only `mod.rs:7` and `mod.rs:24`;
  `mod.rs:37` since commit 13b).
  Proof (review fix, commit 13e): walls were tested only to the right and upward, and the neck rule with one steer;
  mutants running Down off the board (a panic), wrapping Left, and checking a steer against the pending turn instead
  of the heading moved (so Up then Left within one tick turned into the neck) passed every test.
  `every_wall_ends_the_round` steps a snake into each of the four walls, and
  `a_second_steer_before_a_step_cannot_turn_into_the_neck` steers Up then Left before one step: the head moves up and
  the round goes on. In a scratch copy each of the three mutants, and Up wrapping, fails them.

**11. pi/sim gate scenarios (`pi/sim/tests/gate.rs`; the gate's evidence)**
- [x] `boot_stops` (both configs): `run-of-6-startup` → `halt` naming RepetitionCount, startup stage, sample 505;
  `apt-62-startup` → `halt` naming AdaptiveProportion, startup stage, sample 500. Neither names a HAL error.
  Proof (commit 11): `boot_stops_halt_with_cores_startup_verdicts` passes in both configurations (17 steps, 6
  presents, 8 dead keys): boot, a black frame, then `halt` showing exactly "hwrng health test failed: Repetition Count
  Test in the startup stage at sample 505", and after a power cycle "... Adaptive Proportion Test in the startup stage
  at sample 500"; neither shows any `HalError` text, nothing is held, no element is Protected, and all 8 keys are dead
  on `halt`.
- [x] `runtime_stop` (both configs), a throwaway run:
  1. Mixed, 12 words; `coldcard-50` as the rolls; Check now → seal card → Match found → `collision` → privacy gate →
     `collision-qr` → Add fresh entropy.
  2. Step 4 reads `run-of-6-continuous` → `halt` naming RepetitionCount, continuous stage, sample 1505.
     `holds_secrets()` is false, a black frame came first, and every key is dead.
  3. `PowerCycle` → boot → Dice-only seed → `dice` shows "0 / 50": a power cycle drops the 99-roll flag, as documented.
  4. `PowerCycle` → boot → New seed → an hwrng read fault in step 4 → `halt` with the HAL's text (review fix, 11c).
  Proof (commit 11): `runtime_stop_halts_and_a_power_cycle_forgets_the_99_roll_minimum` passes in both configurations
  (56 steps, 296 presents, 98 dead keys): after the collision and Add fresh entropy, the restart's step 4 reads
  `run-of-6-continuous` (behind a counting boot and first session) and, after a black frame, halts showing exactly
  "hwrng health test failed: Repetition Count Test in the continuous stage at sample 1505", with `holds_secrets()` and
  `keeps_wiped()` false and all 8 keys dead; after `PowerCycle` a dice-only seed's dice screen shows "0 / 50 rolls,
  0.0 bits".
  Proof (review fix, commit 11c): no test read an hwrng fault after boot, so a mutant that skipped a failed step 4
  read and kept collecting (rule 3) passed both configurations. Step 4 above now arms `Fault::HwRng` on `hwrng` after
  another power cycle: a black frame, then `halt` showing exactly "hwrng read fault", with `holds_secrets()` and
  `keeps_wiped()` false; the scenario passes in both configurations (72 steps, 303 presents, 98 dead keys). That
  mutant, in a scratch copy, now fails it: 25 `hwrng` presents and no black frame.
- [x] `drill_12`, a vector run (the duplicate-seed drill).
  - Release config: the stick's `with-dice-50` gives `snapshot-failed` with `NoRegistryKey`'s text. The scenario says
    so and ends.
  - Registry config:
    1. `flipped-signature-r` and `with-dice-50` on the stick: `usb-pick`, `snapshot-failed`, then `snapshot-loaded`.
    2. Dice-only, 12 words, `coldcard-50` with one undo.
    3. Check now, date Yes → `collision`, with no words screen before it. `collision-qr` carries kcr.json's dice-50
       seal code.
    4. Add fresh entropy → `dice` shows "0 / 99".
    5. `coldcard-99`, Check now, date No, seal card, Cannot check → "0 / 99".
    6. `coldcard-99`, Check now, Yes → `check-clear`: "No collision for seal 9FHYMCQA as of 2026-03-01."
    7. The words equal `dice-99-words12`; read-back from the screen model.
    8. Steps 11-13 skipped; checklist; `power-off`.

  Proof (commit 12): `drill_12_catches_dice_50_before_any_word_and_restarts_at_99` passes in both configurations
  (release: 14 steps, 9 presents; registry: 196 steps, 1,393 presents, 164 dead keys). The undo shows "10 / 50 rolls,
  25.8 bits"; the date line precedes each snapshot reveal; `collision` comes with no words screen presented in the run,
  and `collision-qr` is `.../register#c=B98KT954NNYSS6APNPZWCYY0VA`; after No, the seal card's check QR carries
  `dice-99-words12`'s T and a 16-hex nonce; Cannot check keeps "0 / 99"; then "No collision for seal 9FHYMCQA as of
  2026-03-01.", the words, their read-back and `power-off`.
- [x] `dice_24_code` (both configs), a vector run covering the code path, the read-back drill and the exports:
  1. Dice-only, 24 words, `coldcard-99`, with Done refused at 98 rolls.
  2. Check now with no snapshot; the seal pages.
  3. A wrong code (G with its last symbol changed) → `code-wrong`, URL unchanged. Then G from the mock checker →
     `check-clear` with the code-path text.
  4. 24 inserts, with `device-swap` and device labels, equal `dice-99-words24`.
  5. 31 s on an insert → `cover` → one press → the same page.
  6. Read-back, each mistake then corrected (the first 11 words equal `dice-99-words12`'s):
     - "vari" for "various" passes and shows "various";
     - "tap" for "tape": should have a letter;
     - "mirc" for "mercy": mirror misread;
     - "taga" for "tag": should be blank;
     - one wrong letter.
  7. `wallet`.
  8. Backup: one wrong confirm pick, a write fault, Retry, verified. The stick then holds the verified `.age` and,
     since commit 13's removal fault (a lead decision), the one file whose removal failed, which backup-failed says
     stays, and nothing else; `decrypt_backup` of the verified one with the shown passphrase gives the session's
     fingerprint.
  9. Watch-only with a typed BIP39 passphrase (a different fingerprint); both QR payloads equal core's `qr_text`, and
     `receive_descriptor` + line feed + `change_descriptor`.
  10. `register-qr`; checklist; `power-off`.

  Proof (commit 12): `dice_24_code_reads_back_every_mistake_and_exports` passes in both configurations (303 steps, 41
  screens, about 1,130 presents (the code typed varies with the nonce), 215 dead keys). Beyond the items above: the
  BIP39 passphrase "Tr3zor!" is typed over all three ASCII grid pages; the summary's fingerprint differs from the
  wallet's; the account QR equals core's `qr_text` and the descriptor QR `receive_descriptor`, a line feed and
  `change_descriptor`, both from a separate core session on the same rolls and passphrase; `register-qr` is
  `.../register#c=C3ER95M4JV2N4TCPBRRG41J74W`; the checklist names both devices.
  Proof (commit 13, a lead decision): `Fault::Remove` fails only the removal of the file just written, which stays
  (`stick`'s `a_failed_removal_leaves_the_file_just_written_once`). After the corrupt read-back, `dice_24_code` now
  retries into another corrupt read-back whose removal fails: backup-failed shows "The file stays on the stick: the
  file could not be removed from the USB stick", and the stick's last three calls write, read back and remove one
  `.age` name, still the stick's one file. Retry then writes the verified backup, so the stick ends with that file
  and the verified one, which the shown passphrase opens to the wallet's fingerprint. It passes in both
  configurations (339 steps, about 1,140 presents, 215 dead keys); in a scratch copy, a backup-failed without that
  line fails it (step 296).
- [x] `skip_and_idle` (both configs), a vector run:
  1. Dice-only, 12 words, `coldcard-50`; Check now → seal card → Match found → `collision-qr` → Add fresh entropy →
     "0 / 99".
  2. `coldcard-99`; Skip → `skip-confirm` → privacy gate with the note → words.
  3. Wait 600 s: `cover` at 30 s, `idle-warning` at 540 s, `idle-wiped` at 600 s; `holds_secrets()` is false.
  4. Dice-only seed → "0 / 50": Skip dropped the kept `Wiped`.

  Proof (commit 12): `skip_and_idle_skip_drops_the_kept_wiped_and_the_idle_wipe_the_words` passes in both
  configurations (66 steps, 706 presents, 94 dead keys).
- [x] `mixed_12_restarts` (both configs), a throwaway run on the counting stream:
  1. Continue is refused before the bar is full.
  2. Snake is open when the quota fills, and the quota closes it.
  3. `commitment`; `coldcard-50` as the rolls.
  4. Check now → seal card → Match found → `collision` → `collision-qr` → step 4 again → "0 / 99".
  5. Check now → Cannot check → "0 / 99".
  6. 9 minutes on `hwrng` → `idle-warning`; a key keeps the session.
  7. 10 minutes in `Rolling` → `idle-wiped` → New seed → "0 / 99".
  8. Check now → seal card → G from the mock checker → `check-clear` → privacy gate → words → read-back from the
     screen model.
  9. Exports skipped except Reveal D → the verify.py tie (next item) → `power-off`.

  Proof (commit 13): `mixed_12_restarts_keep_99_rolls_through_cannot_check_and_the_idle_wipe` passes in both
  configurations (218 steps, 34 screens, about 1,530 presents (the code typed varies with the nonce), 172 dead keys):
  before the quota hwrng offers "Play while you wait" and no Continue; Snake opens, is steered, and the first hwrng
  after it has the full bar and Continue; steps 3-7 as before; then the code, the words read back from the screen, the
  exports skipped but D, reveal-d's layout held to the capture set's specimen, the tie, and power-off.
- [x] verify.py tie (todo.md:3491; carried), from `mixed_12_restarts`' last session:
  - C from the `commitment` model, D from `reveal-d`'s, and the rolls from the script;
  - piped into `python3 -I tools/verify/verify.py mixed --words 12` (stdin is a pipe, so verify.py reads lines from it),
    which must exit 0;
  - its insert lines must name the session's words in order, and its Seal ID must equal that session's `seal-id`
    page;
  - compared in memory, never printed.

  Proof (commit 13): `verify_py_tie` (gate.rs) types C (the last commitment model's 16 groups on one line), D
  (reveal-d's) and `coldcard-99`'s rolls into `python3 -I tools/verify/verify.py mixed --words 12` through a pipe and
  keeps its output in memory: exit 0, the 12 insert lines' words equal the inserts shown, and the seal-id line's
  Seal ID equals the seal-id page's. The assertion's message is fixed, so nothing is printed. It passes in both
  configurations, and the C-zeros mutant (Steps 4-6) fails it.
  Proof (review fix, commit 13f): output that was not UTF-8 panicked through `expect`, whose message is the error's
  `Debug`: every byte of the output, the words and the Seal ID among them. It now fails the assertion's fixed message
  instead, the bytes kept in a `Zeroizing` buffer and read in place. In a scratch copy with verify.py swapped for a
  script printing an insert line, a seal-id line and a 0xff byte, the test printed those bytes before and now prints
  only the fixed message (release configuration: "step 209: verify.py mixed recomputes the words and the Seal ID shown
  from C, D and the rolls").
- [x] `wipes_clear_the_stage` (both configs): for one Protected screen of each `Stage` variant that holds a secret
  (`readback-entry`, `backup-passphrase`, `bip39-entry`, the words of a checked backup, `backup-check-entry`), a
  Buttons fault and, separately, a 600 s wait. After each: `holds_secrets()` is false, a black frame was presented, and
  the next model holds no `Protected` element. On `collision-qr`, the idle wipe keeps the kept `Wiped` and the fault
  drops it.

  Proof (commit 12): `wipes_clear_the_stage_of_every_secret` passes in both configurations (761 steps, 3,108
  presents, 158 dead keys): on `readback-entry` with a face typed, `backup-passphrase`, `bip39-entry` with a
  character typed, a checked backup's words and `backup-check-entry` with a face typed, ten idle minutes give the
  cover, the warning, a black frame and `idle-wiped`, and a Buttons fault gives a black frame and `halt`; after each,
  nothing is held and the next model is all Public; `collision-qr` as before.
  Proof (review fix, commit 12d): the idle timer counted from the last key while nothing was held, so after ten idle
  minutes on usb-insert, the stick a user then put in for Check a backup opened the file, showed the privacy gate and
  wiped it in the same tick ("Wiped after 10 minutes without input"; at 9-10 minutes, the warning at once). The device
  noticing a stick is now input, as a key is (`look_for_stick`). The scenario's `backup-check-entry` round puts the
  stick in after 601 idle seconds on usb-insert: the gate stays up with the backup held, then the round goes on as
  before. It passes in both configurations (757 steps, 3,108 presents, 158 dead keys); without the reset, in a
  scratch copy, it fails at that assertion.
- [x] `check_backup` (both configs):
  1. `about`.
  2. `abandon-12`: one wrong entry (refused with core's text), then the first fours of its passphrase → backup.json's
     fingerprint.
  3. With `with-vector-1` loaded (registry config), the lookup count is 1, with its date. The re-check QR on request.
  4. Words on request show ABANDON 0001.
  5. `zoo-24` shows ZOO 2048.

  Proof (commit 12): `check_backup_opens_by_first_fours_and_shows_its_words_on_request` passes in both
  configurations (release: 139 steps, 390 presents; registry: 149 steps, 397 presents); see Check a backup above.
- [x] `every_screen_is_expected`:
  - The union of `Expect` ids over every scenario built for the active configuration equals `ScreenId::ALL` (registry
    config), or `ALL` minus `snapshot-loaded` and `snapshot-date`, listed by name (release config).
  - Each scenario test fails on any unmet `Expect`, so the union is really reached.

  Proof (commit 13): it passes in both configurations (see the Screen inventory item).
- [x] `drill_12_repeats`: `drill_12` run twice in one test; every presented frame is identical except `seal-qr`'s (the
  nonce). This is the reproducible subset.

  Proof (commit 13): it passes in both configurations: the two runs present the same screens at the same steps
  (release: 9 presents; registry: 1,393), and every frame's SHA-256 is the same but the one seal-qr frame's
  (registry configuration), which differs: a fresh nonce.
- [x] `capture_set` (`#[ignore]`, run on request, Q30 (g)): every scenario of the active configuration, in order, into
  `$CARGO_TARGET_TMPDIR/pi-sim-captures/<config>/`, cleared first.
  - One PNG per present: `<scenario>/NNN-<screen-id>.png`.
  - Protected frames of throwaway runs are placeholders. `reveal-d` is added once as a specimen drawn from
    keepcrypt.json's public `d-00-1f`, labelled so.
  - A static `index.html`: configuration, crate version, and per PNG its number, scenario, step, screen id, class,
    placeholder or specimen flag, and SHA-256; the first capture of every screen id first. It holds no screen text.

  Proof (commit 13): `cargo test -p keepcrypt-pi-sim --locked --features keepcrypt-core/test-registry --test gate --
  --ignored --exact capture_set` wrote 11,530 PNG files (the nine scenarios' 11,529 presents and the reveal-d
  specimen) of all 62 screens, and index.html (11,593 rows: each screen's first capture and the specimen, then every
  capture), to target/tmp/pi-sim-captures/registry/: 1.9 GB in 221 s on this Mac. The panel's capture mode writes
  them, numbered on across power cycles; `Scenario::protected` makes `runtime_stop`'s and `mixed_12_restarts`'
  Protected frames placeholders; `mixed_12_restarts` holds the specimen's layout to the app's reveal-d.
  Proof (review fix, commit 13g): nothing checked the numbering across power cycles: with a power cycle numbering from
  0 again, earlier PNG files were overwritten and `capture_set` still passed, its index naming files that show other
  screens. It now checks, per scenario, that every present's file name is its own and that the folder holds those
  files and nothing else. In a scratch copy (release configuration) that mutant fails it at `boot_stops` (3 file names
  for 6 presents), and unmutated it passes in 183 s with 9,625 PNG files.

  Proof for this group: both configurations' test output, with per-scenario step, screen and dead-key counts; the
  capture set and index under Review.

**12. pi/sim interactive mode (the bin)**
- [ ] `keepcrypt-pi-sim live --out DIR`:
  - keys from stdin lines: `w a s d`, Enter, `1 2 3`, and `t600` to advance 600 s;
  - rewrites `DIR/live.png` per present and prints only the screen id;
  - every Protected frame is written as the placeholder, in every run, vector or not;
  - a "SIMULATOR · NOT FOR REAL FUNDS" strip on every screen, and "SIMULATOR" beside "TEST REGISTRY" when the build
    carries the test key (group 16);
  - the counting hwrng;
  - reads no file: its RAM stick starts empty, so snapshot import and Check a backup can only see a backup written in
    the same live session;
  - it computes no go-ahead code;
  - the bin's screen-id line and the tests' `report` (tests/report/mod.rs: the count line and the render timings) are
    pi/sim's only print sites (`#[expect]` on each);
  - this binary is the one group 14 scans.

  Proof: a unit test that live mode writes the placeholder for a Protected frame; a short session pasted under Review
  (screen ids only).
  Proof (commit 14; the box stays open for the strip's wording, group 14's scan and the Review session): the bin runs
  pi/app's `App` over core on `SimHal` (counting hwrng, an empty stick in the slot from the start, `SimHal::live`).
  tests/hal.rs's live-mode test presents about, an insert showing a public vector word, and about: each is written to
  `live.png`, the insert as `placeholder(words-insert)`'s bytes and never its frame's, the others as drawn, and the
  folder holds `live.png` alone; `SimHal::live` takes no `ProtectedFrames`, and the mutant that writes it as drawn
  fails the test. tests/live.rs runs the built bin: a Mixed run to the first insert, then `t600`, prints only screen
  ids (`boot`, `home`, `length`, `wait`, `hwrng`, ..., 101 `dice`, ..., `privacy-gate`, `words-insert`, `cover`,
  `idle-warning`, `blank`, `idle-wiped`) and leaves `live.png` alone; any other command line, or a line that is no
  input, ends it with the usage. main.rs's 3 unit tests pin the inputs and the command line. Release build for the
  host stand-in, `aarch64-apple-darwin`, with `--features keepcrypt-core/test-registry`: `--artifact` gives the
  registry marker and `TestKey` (exit 1), no stub marker, `_getentropy` imported; `KC_SIMULATOR_DO_NOT_SHIP` is in the
  binary, and with group 13's marker list the same scan gives exactly the three expected hits. Without the test key
  it scans clean. The strip reads "SIMULATOR" (Q33 (j); pi/app's renderer), not "SIMULATOR · NOT FOR REAL FUNDS",
  which cannot share the strip with "TEST REGISTRY" (until commit 20, below); the placeholder carries no strip.
  Proof (review fix, commit 13h): "scans clean" was commit 14's scan, before group 13 put `KC_SIMULATOR_DO_NOT_SHIP`
  on the marker list; since commit 15 that build gives exactly the simulator marker (group 13's proof).
  Proof (review fix, commit 14b): a refused command line or input line made `main` return an error, which std printed
  on stderr ("Error: usage: ..."), an output path beside the bin's one print site (Q31 (i)). The bin now exits with
  status 2 and prints nothing more: tests/live.rs checks status 2 and an empty stderr for each refused command line,
  and for a line that is no input also the screen ids before it. The bin's docs no longer say every screen but the
  placeholder carries the SIMULATOR banner: the black frame of a wipe, which live mode writes too, carries none.
  Proof (review fix, commit 14c): nothing checked that live mode's stick is in the slot from power-on; deleting
  `insert_stick` from the bin passed every test. `live_mode_starts_with_an_empty_stick_in_the_slot` opens Home's
  "Check a backup" and finds usb-pick (no backup on the stick) after usb-insert, then Home; in a scratch copy, the bin
  without its stick fails it (usb-insert, then Home).
  Proof (commit 20; the box stays open for group 14's scan and the Review session): the strip's wording is group 16's.
  Live mode as Commands run it, the release configuration, shows "SIMULATOR · NOT FOR REAL FUNDS" alone: the bin's
  hardware under its `App` presents boot and home with that strip and writes each to `live.png` as drawn
  (tests/hal.rs, `live_mode_shows_the_builds_strip_and_writes_it_to_live_png`); with the test key the same test
  finds "TEST REGISTRY" beside "SIMULATOR". The bin's docs name the long label.

**13. Gates: banned-API rules (Q31 (e); rules 1, 3, 6)**
- [x] `scripts/banned-api-check.sh`, each rule with hit and clean fixtures in `scripts/testdata/banned-api/`:
  - A new `Shell` category (prefix `shell-`, added to the selftest's case statement, the `cats` regex and the
    every-category list):
    - in `pi/app/src/games/`, any of the tokens `Session`, `Wiped`, `add_extra`, `add_hw_samples`, `ceremony`,
      `SystemTime` or `Instant`;
    - `game_random` named anywhere outside `core/src/source.rs`, `core/src/lib.rs`, `core/tests/`,
      `core/examples/release_probe.rs` and `pi/app/src/games/`;
    - `Session::new` in pi/app/src outside `pi/app/src/app.rs`, or a second time in it.
  - Rule1 gains the hash ban: `HashMap`, `HashSet`, `RandomState`, `DefaultHasher`, `hash_one` and `BuildHasherDefault`
    in any .rs file under `core/src`, `ffi/src` and `pi/app/src`. core/src/pool.rs's test switches to `BTreeSet` in the
    same commit.
  - The `#![forbid(unsafe_code)]` line check (:567) extends to `pi/app/src/lib.rs` and `main.rs` whenever `pi/app/`
    exists. `fresh()` also writes both files with the line, so `rule1-lib-rs-absent` (an empty directory) still gives
    exactly one hit. New fixtures `rule1-pi-app-lib-without-forbid` and `rule1-pi-app-main-without-forbid`, each one
    file overriding `fresh()`'s copy.
  - The artifact marker list (:734) gains `KC_SIMULATOR_DO_NOT_SHIP`, with an artifact selftest case.
  - Q31 (h)'s routes, if approved.
  - The Rule1 comment (:97) names `game_random`.

  Proof: `--selftest` with every new fixture firing and the category list complete; the gate clean on the tree; Rule1
  still hits its `pi/app/src/games.rs` and `games/snake.rs` getrandom fixtures; canaries 61/61.
  Proof (commit 15): `banned-api-check.sh --selftest` passes 415/415 (346 before) under sh and dash, 69 new cases,
  each exactly one hit or clean:
  - Shell, 25 hits: the 7 games words in `games/`, and `Session` in `games.rs`, the module's other layout; `game_random`
    in pi/app outside `games/`, pi/sim, `core/src/session.rs`, `core/src/source/mod.rs`, another core example, ffi,
    Kotlin and a test name; `Session::new` in another pi/app file, in `app/ready.rs`, spaced, in a comment, and twice in
    `app.rs` (the second hits); the release probe with no call, a `//` and a `/*` commented-out call, and no probe at
    all (lead decision, stage-A finding 9: the probe must call `game_random` on a line that is not a comment, so
    dropping the call fails the gate). `clean-shell-allowed` holds every allowed place and a near miss per boundary.
  - Rule1, 10 hits: one per hash word, spread over `core/src`, `ffi/src` and `pi/app/src`;
    `rule1-pi-app-lib-without-forbid`, `rule1-pi-app-main-without-forbid` and either file absent;
    `rule1-lib-rs-absent` still gives exactly one hit; `clean-hash-outside-shipped-src` and `clean-no-pi-app` pass.
  - Q31 (h), 9 network fixtures (18 cases) and 12 clipboard fixtures: `logging.config` and
    `multiprocessing.managers` (full and own names) and 5 dotted-name shapes, each also clean under `registry/`;
    `selection_own`, Tcl's clipboard string (call and eval), `clipboard_set`, JXA's `theClipboard` and
    `setTheClipboardTo`, and `gcb`/`scb` in `.ps1`, `.psm1`, `.PS1`, a powershell line in either case and a pwsh shell
    line; clean-near-misses gains a near miss per new pattern.
  - Artifact: `artifact-marker-simulator-text`.
  In scratch copies with the artifact selftest stubbed, each of 89 mutants (every new word, alternative, boundary,
  path, letter class, dispatch and the `fresh()` and `expect()` changes) turns the selftest red, and so does dropping
  `KC_SIMULATOR_DO_NOT_SHIP` from the marker list in a full run. The gate is clean on the tree; on a copy it names
  pool.rs's two `HashSet` lines, app.rs's call once the old doc line (`Session::new` in prose) is back, the probe
  without its call, main.rs without the ban, a Shell word in `games/snake.rs` and `game_random` in pi/sim.
  Rule1 still hits `rule1-getrandom-in-pi-app-games-rs` and `-games-dir`. core/src/pool.rs's test uses `BTreeSet`
  (`every_bit_of_the_os_record_reaches_d` passes in `cargo test --workspace --locked` and with `--features
  test-sources`). Commit 14's host stand-in scan, re-run with the new marker list: the `aarch64-apple-darwin`
  release simulator with `--features keepcrypt-core/test-registry` gives exactly `Marker: ...
  KC_TEST_REGISTRY_DO_NOT_SHIP`, `Marker: ... KC_SIMULATOR_DO_NOT_SHIP` and the `TestKey` hit (exit 1), no stub
  marker, `_getentropy` imported; without the test key, only the simulator marker. Canaries 61/61; `cargo llvm-cov`
  97.38% of core's lines, over the 95% floor.
  Proof (review fix, commit 15b): `Session::new` matched only that spelling, while core's `impl Session<Collecting>`
  also takes `Session::<Collecting>::new(..)` and `<Session<Collecting>>::new(..)`: the security review's mutants, a
  restart through the turbofish in app.rs and the qualified path in `app/ready.rs`, compiled and the gate stayed
  clean. The pattern now takes the state named either way (its brackets hold no `;`, `=`, `(` or `)`), with fixtures
  `shell-session-new-turbofish`, `-qualified-path` and `-turbofish-twice-in-app` (spaced) and four near misses in
  `clean-shell-allowed`. `--selftest` passes 418/418 under sh and dash; the gate is clean on the tree and names both
  mutants; in a scratch copy with the artifact selftest stubbed, the pattern without the `::` before the brackets,
  without the brackets, or letting them hold `=`, or `(` and `)`, each turns the selftest red.
  Proof (review fix, commit 15c): the games' words named core's types and std's clocks, not the app's own holders:
  `Held` and `Stage` are `pub` in the crate-private `app`, so a game function taking `&mut crate::app::Held` reached
  the live session (the security review's mutant called `undo_roll` on it), and `hal::Clock`'s `now_ns` is a clock,
  with the gate clean. The games' words gain `Stage`, `Held`, `App` (its `hal()` reaches the clock), `Clock` and
  `now_ns`, with a `shell-games-*` fixture each and near misses in `clean-shell-allowed`. `--selftest` passes 423/423
  under sh and dash; the gate is clean on the tree and names the mutant; in a scratch copy with the artifact selftest
  stubbed, dropping any one of the five words turns its fixture red.
  Proof (review fix, commit 15d): the release probe's check passed a call that sat only in a trailing `//` comment
  (`Ok(()) // game_random(..)`) or on its own line inside a `/*` ... `*/` block: it skipped only lines starting with
  `//` or `/*`. An awk pass now drops every `//` comment to the end of its line and every `/* */` comment, nested and
  over lines as Rust's are, before the call is looked for; a `//` or `/*` in a string literal can only drop a call.
  New fixtures: `shell-release-probe-call-after-line-comment`, `-in-multiline-block-comment` and
  `-in-nested-block-comment`, and `clean-release-probe-call-after-closed-comments` (a `/*` inside a doc line, then a
  call after a nested block that closes and before a `//`). `--selftest` passes 427/427 under sh and dash (macOS awk;
  CI's mawk runs the same POSIX awk); the gate is clean on the tree and names both of the review's probe edits; in a
  scratch copy with the artifact selftest stubbed, the pass without nesting, without `//` comments, with block
  comments ending at the line's end, or with a `/*` dropping the rest of its line, each turns the selftest red.

**14. CI, CODEOWNERS and the commands of record (Q31)**
- [ ] `test` job, after its two existing steps:
  - `cargo test -p keepcrypt-pi-sim --locked --features keepcrypt-core/test-registry`;
  - a release build of the sim for `x86_64-unknown-linux-gnu`, in its own target dir, with
    `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='--cfg getrandom_backend="linux_getrandom"'`, as canaries.sh's
    build_probe does;
  - then `scripts/banned-api-check.sh --artifact x86_64-unknown-linux-gnu <sim>`. It must exit 1 with exactly three
    hits: `Marker: ... KC_TEST_REGISTRY_DO_NOT_SHIP`, `Marker: ... KC_SIMULATOR_DO_NOT_SHIP` and the `TestKey` hit,
    and no `KC_TEST_SOURCE_DO_NOT_SHIP`.
  - This scan shows the expected markers and no foreign RNG crate symbol. It cannot see std's OS-seeded hashing; the
    hash ban (group 13) covers that in the shipped crates' sources (core, ffi, pi/app), and pi/sim's own code never
    ships (review fix, commit 16b).

  Proof (commit 16; the box stays open for CI, the first x86_64 Linux build): the three steps follow the two existing
  ones; the scan step needs exit 1, the three hit lines, `3 hit(s) in 1 file(s)` and no stub marker. Ruby's YAML
  parser reads the workflow, and every job name, `needs`, `if` and matrix leg is unchanged. Host stand-in,
  `aarch64-apple-darwin` (no cfg, as build_probe on macOS): the registry-config run passes (63 tests, 2 ignored, 15 s);
  the release build in `target/pi-sim-scan` takes 10 s; the step's own script, with only the triple swapped, prints
  exactly the registry marker, the simulator marker and the `TestKey` hit and passes. It fails on a build without the
  test key (1 hit), a copy with the stub marker appended (4 hits), a clean file (exit 0) and a missing file.
  Proof (review fix, commit 16b): the step's comment said the grep gate's hash ban covers the std hashing this scan
  cannot see, but the ban reads only core/src, ffi/src and pi/app/src: in the plan review's scratch copy a `HashMap`
  in pi/sim/src/main.rs, the scanned binary's own code, left the gate clean. The comment now says the ban covers the
  shipped crates' sources and pi/sim's own code never ships; no command changed, and Ruby's YAML parser still reads
  the workflow.
- [ ] `cross` job: on the leg whose crates include `keepcrypt-pi`, also
  `cargo build --release --locked -p keepcrypt-pi --lib --target "$TARGET"`, and scan
  `libkeepcrypt_pi.rlib` with the core artifacts. It must be clean (an archive needs no OS import).
  - The comments in `test` and `cross` name M3. No other job command changes.

  Proof (commit 16; the box stays open for CI's first ARM run): the build step runs where `matrix.crates` holds the
  word `keepcrypt-pi` (the ARM leg only), and the scan step adds the rlib on the same word match, so the other legs
  scan the same two files as before. Host stand-in, `aarch64-apple-darwin`, with the scan step's own script: core's
  rlib, the probe and `libkeepcrypt_pi.rlib` scan clean (2 archives, `_getentropy` imported by the probe); with the
  ffi legs' crates it scans the two core files; with the pi rlib missing it fails.
- [x] `.github/CODEOWNERS` adds `/Entropy/pi/sim/`.

  Proof (commit 16): the line follows `/Entropy/pi/app/`, same owner and form; GitHub's
  `codeowners/errors` for the PR head is for the lead after the push.
- [ ] CLAUDE.md Commands add:
  ```bash
  cargo test -p keepcrypt-pi-sim --locked --features keepcrypt-core/test-registry   # the gate run, full drill
  cargo test -p keepcrypt-pi-sim --locked --features keepcrypt-core/test-registry --test gate -- --ignored --exact capture_set   # captures in target/tmp/pi-sim-captures/
  cargo run -p keepcrypt-pi-sim --locked -- live --out target/pi-sim-live   # Protected screens are placeholders
  ```
  CLAUDE.md rule 1 names `game_random` and says it is never used for dice, D, nonces, passphrases or any pool input
  (Q27).

  Proof (commit 17; the box stays open until the runs are under Review, as M2's Commands item did): the three lines
  as planned, under a header naming `cargo test --workspace` as the simulator's release configuration, with live
  mode's stdin inputs on a continuation line. The `TRYBUILD=overwrite` line gains `--locked` (commit 4's command) and
  also allows an owner-approved API change (M3's borrowing restart; lead decision). Rule 1 is unchanged: since commit
  6 (28a0c5d) it names `game_random`, its own `getrandom` call, no pool, and never dice, D, nonces, passphrases or any
  pool input (Q27 (a)). Run as written: the registry-config run passes (gate 16 passed and 1 ignored, hal 6, live 2,
  units 36 and 3; 15 s); `capture_set` passes in 216 s, writing 11,528 PNG files and `index.html` under
  `target/tmp/pi-sim-captures/registry/`; the live run, fed live.rs's 111-line session on stdin, exits 0 and prints
  only screen ids, 140 of them (`boot` to `idle-wiped`), leaving `target/pi-sim-live/` holding only `live.png`; the
  `TRYBUILD=overwrite` run passes all 23 fixtures and leaves `core/tests/compile_fail/` unchanged.
  Proof (review fix, commit 17b): the Commands still described the gate as RNG, network and clipboard APIs and the
  release-artifact scan as core's two files, after commits 15 and 16. The gate's line now names std's OS-seeded
  hashing and the Shell category; the scan block adds the Pi target's pi/app rlib, scanned with core's two files, and
  the test job's test-registry simulator build and scan; the live line says a refused line ends it with exit status 2
  (commit 14b). Run as written on the host stand-in, `aarch64-apple-darwin`: the three release files scan clean
  (`_getentropy` imported by the probe, 2 archives), and the simulator gives exactly the registry marker, the
  simulator marker and the `TestKey` hit (exit 1).
- [ ] Runtime budgets, measured against group 0's baseline:
  - `test` grows by at most 6 minutes;
  - `gates` stays within 10 minutes (12 if Q31 (f)'s fallback is approved);
  - coverage stays at 95% of core's lines.
  - If a budget is missed, stop and re-plan here.

  Proof: all 14 required check runs green on the PR head, with unchanged names; job times pasted; each command run as
  written and pasted.

**15. KEY2 "back" on the go-ahead code and backup-passphrase entry (the owner's decision of 2026-10-13; Q32 (a) as
amended; rules 5, 6)**
- [x] `screen.rs`: `KeyMap::GRID_BACK`, the grid map with KEY2 "back", for code-entry and backup-check-entry;
  readback-entry and bip39-entry keep `GRID`, with KEY2 dead.
  - The footer must still fit the 240 px panel. With today's labels the grid map and KEY2 make 46 characters
    ("^v<> cursor  OK type  1 delete  2 back  3 done", 276 px), and backup-check-entry offers all five at once (type and
    done both, at an entry's third letter). So the four grids share shorter labels that fit in full, for example
    "^v<> move  OK add  1 del  2 back  3 done" (40 characters, 240 px, as long as the words' footer); "move", "type",
    "del", "back" and "done" would still be 41 (246 px).
  - pi-firmware.md's Buttons table keeps the action names. `KeyMap`'s doc names the footer's shorter labels and the
    two back grids, `every_key_map_is_pinned` pins them, and the footer test still checks every id's legend within
    240 px.

  Proof (commit 19): the four grids share "move", "add", "del" and "done"; `every_key_map_is_pinned` pins
  code-entry and backup-check-entry as "move move move move add del back done" and readback-entry and bip39-entry
  as "move move move move add del - done", and the footer test shows "^v<> move  OK add  1 del  2 back  3 done"
  (40 characters, 240 px) and every id's legend within 240 px (`cargo test -p keepcrypt-pi --locked`: 110 passed).
  In a scratch copy, `GRID_BACK` on readback-entry or bip39-entry fails the pin and `dice_24_code`'s dead KEY2 on
  that grid ("Key2 is offered here"); `GRID` on code-entry or backup-check-entry fails the pin, a unit test and
  `check_restarts` or `check_backup`; "type" and "delete" with KEY2 fail the pin and the footer test.
- [x] `app.rs`: KEY2 in `typing` (where it is `OUT_OF_ORDER` today).
  - On code-entry: the typed code is zeroized in place (`Zeroize::zeroize`, as the other grids' refusals do), then
    check-actions shows. The stage stays `Checking`, with the same session and so the same nonce, and no core call is
    made.
  - On backup-check-entry: the `BackupCheck` stage (the `.age` bytes read and the entries typed, both `Zeroizing`) is
    dropped, then home shows. No USB call is made, so the file stays on the stick.
  - On readback-entry and bip39-entry the model never offers KEY2, and reaching it there stays `OUT_OF_ORDER`.
  - Neither move ends a check or a session (rule 6: only a verified go-ahead reaches `Ready`, and only Match found and
    Cannot check discard), and neither is a refusal or a halt (Q25).

  Proof:
  - pi/app unit tests: with three symbols typed on code-entry, KEY2 shows check-actions, the stage is still
    `Checking` with an empty code, and `check_request().url()` equals the URL before; Enter go-ahead code then shows
    an empty entry, and the same holds after a wrong code's code-wrong and Press. With letters typed on
    backup-check-entry, KEY2 shows home with `holds_secrets()` false. `every_key_map_is_pinned` and the footer test
    pass.
  - `check_restarts` (both configurations), in the session before its first collision (`coldcard-50`, no snapshot):
    Enter go-ahead code before scanning, three symbols typed, KEY2: check-actions; KEY1: seal-qr with the same check
    URL; Press, Enter go-ahead code: nothing typed; a wrong code, code-wrong, Press, KEY2: check-actions again. Match
    found then gives collision-qr with dice-50's report, and Add fresh entropy "0 / 99", as before. Without KEY2 the
    idle wipe was the only way out, and it gave neither.
  - `check_backup` (both configurations): letters typed on backup-check-entry, then KEY2: home, nothing held, the
    stick's files unchanged; Check a backup then opens abandon-12 by its first fours as before.
  - The dead-key probes press KEY2 on the first showing of readback-entry and bip39-entry, with nothing presented,
    and no longer on the two back grids.
  - In a scratch copy, each of these mutants fails a test: KEY2 on code-entry keeping the typed code, showing another
    screen than check-actions, or dropping the session; KEY2 on backup-check-entry keeping the stage; KEY2 offered on
    readback-entry or bip39-entry.

  Proof (commit 19):
  - pi/app: `back_on_the_code_grid_keeps_the_check_and_its_url_and_wipes_the_code` and
    `back_on_the_backup_passphrase_grid_drops_the_backup_and_shows_home` pass as planned (110 unit tests pass).
  - `check_restarts` passes in both configurations (release: 189 steps, about 2,420 presents, 97 dead keys;
    registry: 231 steps, about 2,917 presents, 116 dead keys), with the planned round before the first collision
    ("7QX" typed; the check QR after KEY1 is the one Check now showed; "____-____" on re-entry). Also, in the
    24-word restart after a collision: Enter go-ahead code, KEY2, KEY1 and the seal card paged give one check QR
    three times, and the mock checker's code for it verifies (check-clear for dice-99-words24). The driver keeps
    every check QR's payload (`Record::check_urls`) for these comparisons.
  - `check_backup` passes in both configurations (release: 198 steps, 529 presents; registry: 208 steps, 536
    presents): "a" typed, KEY2, home with `holds_secrets()` and `keeps_wiped()` false, abandon-12.age still on the
    stick, and only list and read calls in its log; abandon-12 then opens as before.
  - The probes no longer press KEY2 on the two back grids; `dice_24_code` presses it as a dead key on
    readback-entry and bip39-entry (`Step::Dead`).
  - In a scratch copy, each planned mutant fails a unit test and a scenario (release configuration's steps): the
    code kept (`check_restarts` step 56, "KEY2 cleared the code typed"), seal-qr shown (step 48, "expected
    check-actions"), the session dropped (step 48, blank and halt), the stage kept (`check_backup` step 26), KEY2
    offered on readback-entry (`dice_24_code` step 125) or bip39-entry (step 314).

**16. The simulator's strip (a lead decision between Q30 (h) and Q33 (j); the strip's part of group 12's open item)**
- [x] `ui/render.rs`: in a simulator build the top strip reads "SIMULATOR · NOT FOR REAL FUNDS" when the simulator
  banner is its only banner (30 characters, 180 px, centred in the whole strip), and "SIMULATOR" beside "TEST
  REGISTRY", each in half the strip as now: the long label and "TEST REGISTRY" (258 px together) cannot share it.
  - Why: Q30 (h) gives live mode "SIMULATOR · NOT FOR REAL FUNDS" on every screen, and Q33 (j) gives "SIMULATOR"
    beside "TEST REGISTRY". The documented live run is the release configuration, so it shows Q30 (h)'s words; the
    registry configuration keeps Q33 (j)'s pair.
  - "TEST REGISTRY" alone, the device (no simulator flag), the placeholder (no strip) and a wipe's black frame are
    unchanged. `hal::BuildInfo::simulator`'s doc and render.rs's module doc follow.

  Proof:
  - render unit tests: the simulator banner alone equals a reference drawing of the long label centred in the strip,
    on the simulator colour, and hides the title; with the test key both banners are drawn as before; each strip
    fits 240 px.
  - pi/sim, both configurations: a drawn present's top strip carries the long label in the release configuration
    (live mode's `live.png` included) and the pair in the registry configuration. Group 12's item then has its
    strip proof; it stays open for group 14's scan and the Review session.

  Proof (commit 20):
  - pi/app (`cargo test -p keepcrypt-pi --locked`: 111 passed): `top_strip` draws the long label when the simulator
    banner is alone and "SIMULATOR" beside "TEST REGISTRY".
    `the_simulator_banner_alone_reads_not_for_real_funds_across_the_strip` pins the long label at 180 px (more than
    half the strip, and 258 px with "TEST REGISTRY"), equal to a reference drawing of it from x = 30 in black on the
    simulator colour across the whole strip; its middle dot is a glyph of its own, not the font's '?'; another title
    gives the same strip, and the content area stays black. `both_banners_fit_the_top_strip_together_and_hide_the_title`
    draws the pair as before (78 and 54 px in 120); its one-banner case is now "TEST REGISTRY" alone, centred at
    x = 81 on the warning colour, and the title without banners is unchanged.
  - pi/sim, both configurations (tests/hal.rs: 7 passed in each):
    `live_mode_shows_the_builds_strip_and_writes_it_to_live_png` runs the bin's hardware (the counting hwrng, live
    mode, the empty stick in the slot) under `App` through boot and home. Each drawn strip is read glyph for glyph
    against the label drawn by pi/app as a title, another path through its renderer: the long label alone in the
    release configuration, "TEST REGISTRY" beside "SIMULATOR" in the registry configuration, and in neither the
    other configuration's strip or "SIMULATOR" alone. Each present was written to `live.png` as drawn.
  - In a scratch copy, "SIMULATOR" alone fails the new pi/app test and the release configuration's hal test; the
    long label beside "TEST REGISTRY" fails `both_banners_fit_the_top_strip_together_and_hide_the_title` and the
    registry configuration's hal test.
  - `hal::BuildInfo::simulator`, `Banners::simulator`, render.rs's module doc and the bin's docs follow.

**17. Review**
- [ ] Plan, security and recompute reviews per stage (core; dependencies and foundation; screens; sim and CI), as in
  M2. Every high and medium finding is fixed, with "Proof (review fixes)" lines.
- [ ] The registry-config capture set, zipped and sent to the owner with its index.
  - Under Review: `git rev-parse HEAD`, an empty `git status --porcelain`, the configuration and the zip's SHA-256.
  - The owner scans every QR capture with a phone (check, register, collision report, re-check, account UR,
    descriptors). Each decoded text must equal core's string, and the Review records it.
  - The owner's verdict, quoted with the date.
  - Gate report against build-plan.md:293, then stop and wait for approval.

**Deferred, with their milestone**
- **M4:**
  - rppal GPIO and mipidsi ST7789 drivers, with the RST and backlight pins checked against the Waveshare schematic;
  - the `/dev/hwrng` reader, and the step 4 Tick from its measured rate;
  - real mount, write, sync and unmount at `/mnt/usb`, with create-new writes and read-only mounts;
  - `mlockall`, and where any `unsafe` code lives (ask first);
  - clearing the ST7789's memory on every wipe;
  - the crash path: `main` blanks the panel before the KATs; whether a panic hook may blank it; the docs say a crash,
    like power-off, drops the 99-roll flag;
  - Buildroot, the reproducible image hash, linking and scanning a release `keepcrypt-pi`, and the image's
    no-simulator-symbols check (pi-firmware.md:76), which the `KC_SIMULATOR_DO_NOT_SHIP` marker makes positive;
  - KAT, snapshot and scrypt timing and peak memory, and the worker-thread decision, with a `Session: Send` assertion;
  - scanning the QRs off the real panel at 3 px modules (the descriptor QR is version 11), the Sparrow and Bitcoin
    Core import, and the getrandom cfg in Buildroot;
  - a real-Pi ceremony checked with `verify.py mixed`;
  - rule 8's wording on device reads (`/dev/hwrng`, `/sys/block`).
- **M5, M6:** `game_random`, `from_first_four` and the borrowing restart through the FFI; the phones keep their `Wiped`
  the same way and decide their own runtime-error rule after Q25.
- **M7:** the birthday-collision job; qrcodegen-no-heap's stack temporaries on the residual list; owner item 13 if no
  source file arrives.
- **M8:** the camera go-ahead QR (`verify_bucket_proof_qr`, `GoAhead::BucketProof`); phase-2 sensors as extras.
- **M9:** the pinned registry key and origin, so release builds can load snapshots.
- **Tetris:** when the owner chooses (Q27 (c)).
- **Later, on request:**
  - an SDL window for the simulator (needs SDL2 and the Zlib licence);
  - a nicer Latin font, generated by a committed script.

### Verification
- [ ] **Gate: a scripted run drives a full ceremony in the simulator.** `drill_12` (registry config), `dice_24_code` and
  `mixed_12_restarts` (both configs) pass steps 1-15 between them.

  Proof: CI test output in both configurations.
- [ ] **Gate: every screen.** `every_screen_is_expected`, against the inventory in group 8.

  Proof: test output.
- [ ] **Gate: seal check with go-ahead code entry.**
  - The code is typed on the grid.
  - A wrong code gives `code-wrong` with the same nonce, and no words screen.
  - The mock checker's G, from a QR whose drawn modules match its payload, reveals the words.
  - The snapshot path confirms the date before every `reveal`.

  Proof: `dice_24_code`, `drill_12`, `mixed_12_restarts`; matrix row "Go-ahead vectors and tampering" (Pi part).
- [ ] **Gate: braille pages.**
  - Insert view and overview for 12 and 24 vector words, with numbered dots, blank faces, lighter letters, mirror flags
    and device labels.
  - The read-back names a mirror misread, a should-be-blank, a should-have-letter and a wrong letter.

  Proof: group 6's mask and label tests, `drill_12`, `dice_24_code`; matrix row "Metal read-back drill" (Pi part).
- [ ] **Gate: button handling.**
  - Debouncer unit tests, and every scripted press runs through the Debouncer as a bounce train.
  - Every screen shows its soft keys.
  - The dead-key probes change nothing.
  - The documented mappings hold: dice KEY1 undoes; words KEY1 toggles the overview and KEY2/KEY3 page.

  Proof: group 5's tests and the probe counts.
- [ ] **KEY2 "back"** (the owner's decision of 2026-10-13; Q32 (a) as amended):
  - from code-entry to check-actions with the same check and nonce and the typed code cleared, after which Match
    found still reports the collision and the restart needs 99 rolls;
  - from backup-check-entry to home with nothing held, and the file left on the stick;
  - no KEY2 on readback-entry or bip39-entry, and every footer within 240 px.

  Proof: group 15's unit tests, `check_restarts`, `check_backup`, the dead-key probes.
- [ ] **The simulator's strip** (a lead decision; Q30 (h), Q33 (j)): "SIMULATOR · NOT FOR REAL FUNDS" when it is the
  only banner, as in live mode's release configuration, and "SIMULATOR" beside "TEST REGISTRY" in the registry
  configuration.

  Proof: group 16's tests.
- [ ] **Gate: waiting-screen game.**
  - Snake runs only in Mixed step 4 and is closed at the quota.
  - Its bytes come only from `game_random` (the Shell grep allows the name only under `pi/app/src/games/`).
  - Every key in Mixed `Collecting`, Snake open or not, is forwarded to `add_extra`: `extra_for`'s unit test plus review
    of its one call site. None after the commitment: the typestate has no `add_extra` there.
  - A `game_random` error halts with no secret held.

  Proof: groups 8 and 10, group 13's grep, `mixed_12_restarts`.
- [ ] **Gate: USB export mocked.**
  - The backup is written (never over an existing name), read back under a read-only mount and verified.
  - A write fault removes only the file just written, and Retry runs under the same passphrase.
  - The stick ends with the verified `.age` and nothing else, but for a file whose removal failed (`dice_24_code`'s
    `Fault::Remove` round, commit 13), which stays, as backup-failed says.

  Proof: `dice_24_code`; group 7's Usb refusals.
- [ ] **Gate: snapshot import mocked.**
  - Registry config: `with-dice-50` loads and drives both the collision and the clear result; a tampered snapshot is
    refused.
  - Release config: `NoRegistryKey`'s text.

  Proof: `drill_12` in both configurations.
- [ ] **Gate: the owner reviews the captures,** with every QR scanned.

  Proof: the owner's verdict and the scan record, quoted under Review.
- [ ] **Runtime failures halt** (Q25; design.md:178): boot and continuous health failures, an injected game error and
  HAL faults all end on `halt` with no secret held.

  Proof: `boot_stops`, `runtime_stop`, `wipes_clear_the_stage`, group 8's unit test.
- [ ] **The 99-roll minimum** (todo.md:2293-2296; Q26):
  - 99 after a Stop;
  - 99 after a Cannot check in the restart after a collision;
  - 99 after the idle wipe in that restart;
  - 50 after Skip in that restart;
  - 50 after a power cycle (documented).

  Proof: `drill_12`, `mixed_12_restarts`, `skip_and_idle`, `runtime_stop`, group 2's tests, group 8's unit tests.
- [ ] **Secrets held by the shell** (rule 5): after the idle wipe and after a fault, the `Stage` holds nothing;
  `Protected` elements appear only on Protected ids in every scenario; live mode never writes a Protected frame.

  Proof: `wipes_clear_the_stage`, the SimHal invariant, group 12's unit test.
- [ ] **Matrix "Full ceremony with offline verification"** (simulator half; the Pi in M4): the verify.py tie exits 0
  with the same words and Seal ID (`mixed_12_restarts`).
- [ ] **Matrix "Duplicate-seed drill"** (Pi part): `with-dice-50` catches `coldcard-50` before any word is shown, and
  the restart needs 99 rolls.

  Proof: `drill_12` (registry config).
- [ ] **Matrix "Watch-only import"** (M3 half): the drawn QR payloads equal core's `qr_text`, and the two descriptors
  on two lines (`dice_24_code`). The import itself is M4.
- [ ] **Matrix "Symbol and stub-marker scan":** release_probe calls `game_random` on all six cross legs (by review: the
  scans would not change without the call, and each leg's scanned rlib holds its code); pi/app's ARM
  release rlib scans clean; the test-registry simulator scans with exactly the registry marker, the simulator marker
  and the test key.
- [ ] **Matrix "Typestate misuse" and "Sealed-state compile-fail tests":** every fixture passes, with the one `.stderr`
  change being the quoted signature; pi/app's gate functions are unit-tested; no scenario reaches a wipe through a
  shell-order mistake.
- [ ] **Carried items:**
  - `Platform::Pi` asserted;
  - test-registry only via `-p` (the manifest pin holds);
  - the date confirmed before `reveal`;
  - the step 4 bar on `hw_bytes_tested`;
  - C and D as 16 groups of 4;
  - the wait-for-prompt text on `reveal-d-offer` and in pi-firmware.md step 14;
  - owner items 13 and 14, and the banned-API routes, decided.
- [ ] **Rules:**
  - 1: only `core/src/source` names getrandom; no std OS-seeded hashing in core, ffi or pi/app; the graph pin is
    unchanged;
  - 3: every halt condition ends on `halt` with no secret held;
  - 5: pi/app prints nothing, buffers are wiped, Protected screens are captured unredacted only from vector runs;
  - 6: only the app's `Stage` holds the typestate;
  - 8: the stick's log shows only `.age`/`.kcr` reads (read-only by the HAL's shape and the simulator's construction;
    the device's mounts are M4's) and create-new `.age` writes; pi/sim reads no file;
  - 10: no manifest turns on a test feature; the simulator marker is in every simulator build;
  - 11: every new crate is approved, vetted and past the cool-off.
- [ ] **CI:** all 14 required check runs green; budgets met; canaries 61/61.
- [ ] **Definition of done** (CLAUDE.md), with proof pasted under Review.

### New dependencies

**How this was checked (2026-10-11)**
- crates.io API reads for versions, dates, licences and features.
- Throwaway lockfiles with resolver 3 and rust-version 1.98.1. The pinned probe for the recommended set
  (`scratchpad/m3-plan/lockprobe/m3pin-noheap/`, autocfg held at 1.5.0) holds exactly these 9 crates plus the two
  members. qrcodegen-no-heap 1.8.1's checksum is `d0e2c0bf8be8a1c4a4f48973dabf26943f05da2bfc2d3180aae62409dbba6f0c`.
- The local RustSec copy (2026-10-09): no advisory for any of them.

**Results**
- Every version was published before 2026-09-27, the cutoff for the 14-day cool-off.
- None has rand, getrandom, log, tracing or a network crate in its normal or build dependencies. rand appears only as a
  byteorder dev-dependency.
- Every licence is on deny.toml's allow-list.
- embedded-graphics has no default features. deny's `all-features` does not reach its optional `defmt`,
  `fixed_point` or `nalgebra_support`.

| Crate | Version | Published | Licence | Why | Vet |
| --- | --- | --- | --- | --- | --- |
| embedded-graphics | 0.8.2 | 2026-02-15 | MIT OR Apache-2.0 | Fonts, shapes, `DrawTarget` (M4's mipidsi uses it); build-plan.md:76 | exemption |
| embedded-graphics-core | 0.4.1 | 2026-02-15 | MIT OR Apache-2.0 | Through embedded-graphics; mipidsi 0.10.0 needs `^0.4.1` | exemption |
| az | 1.2.1 | 2022-07-25 | MIT/Apache-2.0 | Through embedded-graphics (`~1.2.0`) | exemption (isrg has only 1.2.1 to 1.3.0) |
| byteorder | 1.5.0 | 2023-10-06 | Unlicense OR MIT | Through embedded-graphics | import (google, safe-to-deploy) |
| float-cmp | 0.9.0 | 2021-07-21 | MIT | Through embedded-graphics (`^0.9.0`, default `ratio`) | exemption (google: safe-to-run only) |
| micromath | 2.1.0 | 2023-10-31 | Apache-2.0 OR MIT | Through embedded-graphics | exemption |
| num-traits | 0.2.19 | 2024-05-03 | MIT OR Apache-2.0 | Through float-cmp's `ratio` | import (bytecode-alliance) |
| autocfg | 1.5.0 | 2025-06-17 | Apache-2.0 OR MIT | num-traits' build dependency; `--precise 1.5.0` (1.5.1 is not covered) | import (google 1.4.0 + zcash delta) |
| qrcodegen-no-heap | 1.8.1 | 2023-08-20 | MIT | QR encoding into buffers pi/app wipes (Q28 (b)); 1.8.0 yanked the same day | exemption (one file; an owner audit can replace it) |

- Q28 (e)'s "3 imported audits" counts crates (byteorder, num-traits, autocfg). imports.lock gained 4 entries, since
  autocfg's is google's 1.4.0 audit plus zcash's 1.4.0 -> 1.5.0 delta (Proof (commit 7)).
- **New edges to crates already in Cargo.lock** (no new lockfile entry):
  - pi/app → zeroize 1.9.0;
  - pi/sim → keepcrypt-core (no features);
  - pi/sim dev-dependencies → sha2 0.11.0 and serde_json 1.0.151.
- **Not added:** embedded-graphics-simulator, sdl2, image, png, flate2, u8g2-fonts (licence "non-standard"),
  qrcodegen, qrcode, fast_qr.
- **M4 adds**, each with its own approval: mipidsi 0.10.0, rppal 0.22.1 (as a Linux-only target dependency),
  embedded-hal 1.0.0 and spin_sleep 1.3.3.

### Commit order on `m3-pi-sim`
Each commit's proof runs at that commit; scenarios grow with the screens they cover.
1. tasks/todo.md: the M3 plan and the owner's answers to Q25-Q34. The title becomes "milestones M0 to M3".
   1b. tasks/todo.md: the plan review: owner item 14 answered by Q26 (C), the games note done, and the plan's doc
   line citations after commit 2 (888c174).
   1c. tasks/todo.md: the recompute review: release_probe's `game_random` call is review evidence, not scan evidence.
2. docs: the approved edits (Q34), alone, with no code.
   2b. docs: review fixes to commit 2: swb's "Add fresh entropy" halts the Pi on any failure but not on a refusal of
   what the user or a stick supplied, as Q25 says; the sketch's list of free functions that run no KAT group names
   `game_random`.
3. core: `game_random`, its tests and the release_probe call (group 1).
4. core: the borrowing restart, its tests, the regenerated `.stderr` and module docs (group 2).
   4b. tests: the recompute review: check_flow restarts one kept collision `Wiped` twice through the shipped
   `restart`, not only through `restart_with_stub`.
5. core: `from_first_four` and its tests (group 3).
6. CLAUDE.md: rule 1 names `game_random`.
7. pi, sim, supply-chain: manifests, Cargo.lock (autocfg held), vet exemptions and imports (group 4).
   7b. tasks/todo.md: the plan review: the dependency table names num-traits' one import, and the imported audits
   are counted per crate.
8. pi/app: the screen model, `hal`, `frame`, `input`, `#![forbid(unsafe_code)]` (group 5).
   8b. pi/app: the plan review: the idle wipe also clears a Protected screen with nothing held (collision-qr), as
   group 11's `wipes_clear_the_stage` expects.
   8c. pi/app: the recompute review: every key map is pinned, and the docs and a test name no longer say the QR and
   info pages follow the "Buttons" table.
9. pi/app: the renderer and its painters (group 6).
   9b. pi/app: the plan review: the docs say every `Frame` belongs to a `Painter`, not that the `Painter` holds the
   only one (`Painter::new` is public, and pi/sim makes its own).
10. pi/sim: `SimHal`, the PNG writer and placeholder, the marker, the render timing (group 7).
    10b. pi/app, pi/sim: the plan and security reviews: the `Usb` docs make the record of the file just written each
    implementation's duty (a `Written` grants nothing by itself), and the stick clears it at every write attempt.
    10c. pi/sim: the security review: the stick logs reads read-only by construction, so its log is no evidence of
    read-only mounts.
    10d. pi/sim: the security and recompute reviews: capture mode's placeholder flag comes with the bytes it chose,
    and the capture test compares the bytes written.
    10e. pi/sim: the recompute review: the panel log test covers every field of the owned model copy.
    10f. pi/sim: the plan review: the tests' one print site moves to tests/report/mod.rs, for the timing lines and
    group 11's count line alike.
11. pi/app, pi/sim: the app, steps 1-7, halts, restarts, idle, the driver, the mock checker, and `boot_stops`,
    `runtime_stop` and the steps 1-7 parts of the other scenarios (group 8).
    11b. pi/sim: the recompute review: SimHal fails a run whose app's deadline never moves, instead of spinning on
    the virtual clock.
    11c. pi/sim: the recompute and plan reviews: `runtime_stop` also halts on an hwrng read fault in step 4; the
    halts item stays open for the game error.
    11d. pi/sim: the recompute and plan reviews: `mixed_12_restarts` checks the step 4 bar; the steps 4-6 item is
    unticked until Snake and C's check land.
    11e. pi/sim: the security and recompute reviews: the scenarios fail on a secret's text in any Public element, and
    on a secret item marked Public on a Protected screen.
    11f. tasks/todo.md: the recompute review: the step 7 item names the restart checks commit 13's scenarios add
    before it is ticked.
12. pi/app, pi/sim: steps 8-15, the Home side flows, and `drill_12`, `dice_24_code`, `skip_and_idle`, `check_backup`,
    `wipes_clear_the_stage` (group 9).
    12b. pi/sim: the plan and recompute reviews: `dice_24_code` proves step 11's read-back, verify and removal of the
    file just written, and the passphrase generated once.
    12c. pi/sim: the plan and recompute reviews: `check_backup` refuses a wrong passphrase, names a USB fault and a
    backup over 8 KiB, and counts zero registrations.
    12d. pi/app, pi/sim: the security review: a USB stick put in restarts the idle timer.
    12e. pi/app, pi/sim: the plan and security reviews: the overview pages on past word 12 only through
    `device-swap`.
    12f. pi/app, pi/sim: the plan review: a checked backup's last insert labels Press "done", not "read-back".
    12g. pi/app: the plan review: a refused backup passphrase puts the grid cursor back on the first symbol, and the
    docs say where an entry grid's cursor may rest. 5f46a48 rustfmts c171599's assertion.
    12h. pi/app: the security review: a unit test pins the BIP39 passphrase's 100-character cap in its own buffer.
    12i. pi/app: the recompute review: a unit test shows each step's secret dropped when its screens are left.
13. pi/app, pi/sim: Snake; `mixed_12_restarts` in full, the verify.py tie, `every_screen_is_expected`,
    `drill_12_repeats` and `capture_set` (groups 10, 11); `check_restarts` for step 7's restart checks and, with the
    test key, the code after No; and a SimHal fault that fails the removal of the file just written
    (`dice_24_code`).
    13b. pi/app: the security review: the app holds the games' byte source but cannot draw from it (`GameBytes`'s
    field is private to `games`).
    13c. pi/app: the recompute review: a game byte error halts where Snake opens and where a step places food, not
    only at play again.
    13d. pi/app: the security and recompute reviews: the keys step 4 hands to `add_extra` are counted at the app's
    one call site, Snake open or closed.
    13e. pi/app: the recompute review: Snake meets each of the four walls, and a second steer before a step cannot
    turn into the neck.
    13f. pi/sim: the security review: verify.py output that is not UTF-8 fails the tie's fixed message, never printed.
    13g. pi/sim: the recompute review: `capture_set` checks that each present has a file of its own, and the folder
    nothing else.
    13h. tasks/todo.md: the plan review: `dice_24_code`'s step 8 and the USB gate name the file left by the failed
    removal; the step 4 probe count and group 12's scan line are brought up to date.
14. pi/sim: the interactive bin (group 12).
    14b. pi/sim: the plan review: a refused command line or input line ends the bin with exit status 2 and nothing
    printed; its docs name the two frames without the SIMULATOR banner.
    14c. pi/sim: the recompute review: a live session finds the empty stick in the slot from power-on.
15. scripts, core: the Shell category, the hash ban with pool.rs's `BTreeSet`, the pi/app forbid lines, the simulator
    marker, Q31 (h)'s routes, and fixtures (group 13).
    15b. scripts: the security review: the Shell category's `Session::new` also matches the turbofish and the
    qualified path.
    15c. scripts: the security review: the games' code may not name the app's holders of the session or the HAL's
    clock either (`Stage`, `Held`, `App`, `Clock`, `now_ns`).
    15d. scripts: the recompute review: the release probe's `game_random` call counts only outside every `//` and
    `/* */` comment.
16. ci, .github: the `test` and `cross` steps and comments; CODEOWNERS adds `pi/sim/` (group 14).
    16b. ci: the plan review: the `test` job's comment says the hash ban covers the shipped crates' sources, not
    pi/sim's.
17. CLAUDE.md: Commands for M3.
    17b. CLAUDE.md: the plan review: the gate's line and the release-artifact scans describe commits 15 and 16, and
    live mode's refusal.
18. docs, tasks/todo.md: the owner's KEY2 "back" decision (2026-10-13) for the go-ahead code entry and the
    backup-check entry, with no code: pi-firmware.md's Buttons table, step 7 and "Check a backup"; the decision
    recorded under "Raised by stage C's review during M3", Q32 (a) amended, the screen inventory, groups 15 and 16
    and their Verification lines.
19. pi/app, pi/sim: KEY2 "back" on code-entry and backup-check-entry, the grids' footer labels that fit with it, unit
    tests, `check_restarts` and `check_backup` (group 15).
20. pi/app, pi/sim: the simulator's strip reads "SIMULATOR · NOT FOR REAL FUNDS" alone and "SIMULATOR" beside "TEST
    REGISTRY" (group 16; a lead decision).
21. tasks/todo.md: the M3 Review, with pasted proof, the owner's verdict on the captures and the gate report.

Review fixes are listed as N.b entries under the commit they amend.

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

### M1: local proof (2026-10-10, at cfdb24a, commit 28)
Apple M4 Max, macOS, toolchain 1.98.1 (rust-toolchain.toml), python3 3.12.5 and `/usr/bin/python3` 3.9.6, run from
`Entropy/`; the shell scripts also under `dash`. Plan items are ticked above only where the proof below covers them;
each unticked item says what it waits for (the end of this section).

**Suite.** Every command of the stage's suite, on commit 28's tree (commit 29 changes only this file):

```text
cargo fmt --all --check                                                     rc=0
cargo clippy --workspace --all-targets --locked -- -D warnings              rc=0
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings  rc=0
cargo test --workspace --locked                                             rc=0  (18 s)
cargo test -p keepcrypt-core --locked --features test-sources               rc=0  (59 s)
cargo deny --locked check                                                   rc=0  advisories ok, bans ok, licenses ok, sources ok
cargo audit                                                                 rc=0  94 crate dependencies, no findings
cargo vet --locked                                                          rc=0  Vetting Succeeded (14 fully audited, 76 exempted)
sh scripts/check-path-deps.sh             (sh, dash)                        rc=0  clean, 90 packages outside the workspace, all
                                                                                  from crates.io; members exactly core, ffi,
                                                                                  pi/app, pi/sim; no cargo config files
sh scripts/banned-api-check.sh            (sh, dash)                        rc=0  clean, 161 files scanned
sh scripts/banned-api-check.sh --selftest (sh, dash)                        rc=0  selftest: 233 passed, 0 failed
python3 tools/verify/verify.py --selftest          (3.12.5)                 rc=0  selftest passed: 11 checks
/usr/bin/python3 tools/verify/verify.py --selftest (3.9.6)                  rc=0  selftest passed: 11 checks
sh scripts/canaries.sh                    (sh, dash)                        rc=0  PASS: all 54 checks ran
```

**Tests, per binary.** Default features (the release configuration), then `--features test-sources`:

```text
default:       unittests 161 passed, 1 ignored (11.5 s) | ceremony 5 | kat 7 | kcr_release 3 | os_source 2 |
               typestate 1 (23 fixtures) | vectors 4
test-sources:  unittests 188 passed, 1 ignored (19.4 s) | ceremony 5 | check_flow 6 | error_injection 11 | kat 7 |
               kcr 3 (11.5 s) | kcr_release 0 (compiled out under test-registry) | no_panic 9 (8.9 s) |
               no_secret_text 5 | os_source 2 | panic_wipe 4 | source_substitution 5 | typestate 1 | vectors 4
```

The ignored unit test is `backup::tests::age_interop_files`, which `scripts/age-interop.py --core` runs.

```text
typestate (trybuild 1.0.121, toolchain 1.98.1; the same 23 under both feature sets):
  backup_takes_no_passphrase  bip39_passphrase_not_debug_display_clone  braille_views_not_debug_display_clone
  checked_backup_not_debug_display_clone  checking_state_holds_no_secret  confirm_challenge_not_debug_display_clone
  dice_before_commit  new_backup_passphrase_not_debug_display_clone  no_skip_after_check_started  no_struct_literals
  readback_result_not_debug_display_clone  revealed_words_cannot_outlive_their_secret
  seal_code_and_qrs_not_debug_display_clone  sealed_state_holds_no_secret  secret_bytes32_not_debug_display_clone
  secret_mnemonic_not_debug_display_clone  session_not_debug_clone  transitions_consume_the_session
  typed_backup_passphrase_not_debug_display_clone  views_cannot_outlive_their_secret
  watch_only_export_not_debug_display_clone  wiped_holds_no_secret  words_before_finish            all ok
error_injection: the_os_source_failing_halts_and_wipes  short_reads_halt_and_wipe  every_os_read_of_a_ceremony_halts_and_wipes
  every_health_case_through_the_session  the_pi_quota_needs_a_whole_window_of_hwrng
  hwrng_input_on_a_phone_or_in_dice_only_mode  bad_faces_and_a_257th_roll  finish_below_the_minimum
  shell_order_bugs_halt_and_wipe  every_kat_at_new_and_at_restart  every_kat_through_each_free_function   all ok
source_substitution: a_fixed_stub_gives_the_vectors_d_and_c  one_changed_byte_of_any_source_changes_d
  a_changed_source_id_or_a_dropped_extra_changes_d  exactly_64_os_bytes_are_read
  dice_only_e_is_sha256_of_r_whatever_the_stubs                                                     all ok
check_flow: the_code_reveals_the_words_and_a_typo_keeps_the_session
  a_proof_for_another_bucket_retries_and_the_code_still_reveals
  collision_evidence_wipes_the_seed_and_the_report_holds_its_code
  the_restart_refuses_50_rolls_and_accepts_the_99_roll_string  freshness_is_the_shells_warning_not_a_refusal
  a_snapshot_loaded_before_the_ceremony_serves_every_check                                          all ok
ceremony: mixed_mode_on_the_pi  mixed_mode_on_a_phone  dice_only_on_the_pi  dice_only_on_a_phone
  every_export_fails_before_read_back                                                               all ok
no_secret_text: no_seed_word_is_printed  rejected_and_wiped_print_no_bip39_token  every_error_is_listed
  a_planted_leak_is_caught_by_each_check  a_seed_word_inside_a_longer_control_token_is_still_caught  all ok
panic_wipe: a_panic_while_collecting_wipes_the_session  a_panic_while_rolling_or_checking_wipes_the_seed
  a_panic_with_the_words_shown_wipes_them  a_thread_that_ends_normally_wipes_once_without_a_panic   all ok
no_panic: hwrng_samples  dice_faces  go_ahead_codes  bucket_proofs_as_bytes_and_as_ur_text  registry_snapshots
  age_backups  typed_backup_words  read_back_strings  bip39_passphrases_and_registry_dates           all ok
kcr (test-registry): every_snapshot_case  every_proof_case  the_test_registry_key_is_pinned        all ok
kcr_release (default): no_registry_key_is_pinned  a_release_build_is_not_a_test_registry_build
  every_kcr_json_case_gives_no_registry_key (107 cases)                                             all ok
os_source: two_real_sessions_give_different_commitments  two_real_checks_draw_different_nonces    all ok
kat: the_boot_screens_pass and six cross-file agreements (seed, seal and go-ahead, ed25519 and hash, bip84 and
  backup, braille, age)                                                                             all ok
vectors: rolls_json_through_dice_only_sessions  keepcrypt_json_dice_only_cases
  backup_json_and_the_age_cli_files_through_decrypt_backup  seal_json_vector_1_through_a_checked_backup  all ok
```

**Proof per ticked plan item** (unit tests are `module::tests::name`; all pass in the runs above):
- Group 0, answers and doc edits: the answers to Q1-Q12 are recorded under "Needed before M1" (7ac6c8a), the Q10
  doc edits are d7d0393 and the Q13 edits c40a2e3.
- Group 1, profiles and features: the canary static check "core [features] and the root [profile] exactly as
  pinned" passes and the `release-profile` and `test-features-in-manifests` canaries fail as intended; the timings
  are recorded in the item (1.45 s root pass, 0.61 s log2 N 18 round trip).
- Group 1, new crates: Cargo.lock holds 90 third-party packages (46 at M0, so 44 new); one getrandom (0.4.3), one
  digest (0.11.3), one sha2 (0.11.0), one hmac (0.13.0); `cargo tree -p keepcrypt-core --all-features --target all
  -e normal,build,dev -i rand_core` and `-i log` both end with "package ID specification ... did not match any
  packages"; the held versions are locked as planned (ctutils 0.4.2, toml 1.1.6, toml_parser 1.1.3, toml_datetime
  1.1.1, toml_writer 1.1.2, serde_spanned 1.1.1, trybuild 1.0.121, serde_json 1.0.151); the canary graph pins pass
  (ed25519-dalek with no features, curve25519-dalek with `digest` only, getrandom's only dependent keepcrypt-core,
  no serde in core's normal or build graph); deny and vet pass. After refreshing the imports, 11 of the 44 pass on
  imported audits (equivalent, fiat-crypto, inout, rustc_version, semver, serde_spanned, subtle, termcolor,
  toml_datetime, winapi-util, windows-link) and 33 are exemptions, listed for approval under the owner items.
- Group 2: layout (the banned-API gate is clean; the one call to the OS RNG crate is in `core/src/source/os.rs`,
  and its name appears otherwise only in `core/src/source.rs`'s comments, inside the module the gate allows);
  `error::tests::every_variant_displays_its_pinned_text` and `health_failure_names_test_stage_and_index_only`;
  `secret::tests::*` (6) and `session::inner::tests::zeroize_clears_every_field`; the session skeleton in
  `session::tests::new_runs_the_suite_and_keeps_the_settings` and
  `session::inner::tests::the_probe_counts_completed_zeroizes_and_drop_runs_one`; `kat::tests::*` (19) and
  tests/kat.rs; kat.json by verify.py check 5 on both Pythons; the stub by `source::tests::stub::*` (4),
  `source::stub::tests::*` (3) and the canary positive control for its marker (below).
- Group 3: check 6, check 7 and check 4 on both Pythons; `source::tests::*` (credit_policy_table,
  os_source_writes_every_byte_position, constants_and_ids_match_keepcrypt_json, the four stub tests) and
  `source::os::tests::every_os_error_is_a_source_fault`; `health::tests::*` (7, among them
  every_keepcrypt_json_case_in_any_chunking, credit_arrives_per_completed_window and
  a_failed_tester_stays_failed_and_credits_nothing); `pool::tests::*` (4, every_bit_of_the_os_record_reaches_d among
  them); the Pool and Health KATs in `kat::tests::pool_constants_match_keepcrypt_json`,
  `health_cases_match_keepcrypt_json` and `every_group_passes_and_fails_under_its_fault`.
- Group 4: `dice::tests::*` (6); the Seed KAT in `kat::tests::seed_constants_match_keepcrypt_json`.
- Group 5: `braille::tests::*` (16) for braille.rs and the read-back compare (six_sample_inserts,
  readback_keys_are_distinct_and_find_their_word, every_word_reads_back_from_its_own_faces, the_named_misreads,
  every_mirror_flip_is_one_mirror_misread_and_names_the_279, every_blank_face_slip_is_caught,
  prefix_neighbours_never_match_and_49_short_words, text_vectors_and_refusals, a_mismatch_zeroizes_every_field, ...).
- Group 6: check 9 on both Pythons, with every "Spec values" page fetched during M1 (2026-10-09 and 10-10) and its
  SHA-256 recorded in SOURCES.md; `ur::tests::*` (8); `descriptor::tests::*` (bip84_vector,
  bcr_2020_015_shield_and_the_full_example, bip380_checksum_cases, tampered_descriptors_fail_the_self_check, ...);
  the Bip84 KAT in `kat::tests::bip84_constants_match_watchonly_json`.
- Group 7: check 10 on both Pythons; `seal::check::tests::*` (6) and the session's typo test
  (`session::tests::stub::a_typo_then_the_right_code_reveals`, check_flow); `seal::merkle::tests::*` (3);
  `seal::snapshot::tests::*` (7, every_snapshot_case and every_header_bit_flip_and_truncation_fails among them) and
  `seal::date::tests::*`; `seal::proof::tests::*` (3) and tests/kcr.rs; `seal::registry_key::tests::*`,
  `seal::registration::tests::*`, tests/kcr_release.rs (107 cases, NoRegistryKey) and the test-registry positive
  control below (registry marker and key, no stub marker); the four KATs in
  `kat::tests::seal_and_go_ahead_constants_match_seal_json_and_kcr_json`, `ed25519_constants_match_kat_json`,
  `merkle_constants_match_kcr_json` and `a_fault_in_the_s_step_fails_the_seal_group`.
- Group 8: `backup::armor::tests::*` (2) and the refused armor cases of backup.json through
  `backup::age::tests::every_refused_file_gives_its_error`; `backup::tests::passphrase_layouts_match_backup_json`,
  `each_of_the_88_bit_flips_changes_exactly_one_word`, `stub::generate_matches_backup_json` and the
  `backup_takes_no_passphrase` fixture; `backup::tests::plaintexts_match_backup_json` and
  `every_refused_plaintext_gives_its_error`; the Age KAT in `kat::tests::age_constants_match_backup_json_and_cctv`
  and `backup::tests::stub::decrypt_backup_runs_the_age_group`.
- Group 9: tests/ceremony.rs (Mixed and dice-only, Pi and phone, 12 and 24 words); `session::tests::*` (7) and
  `session::tests::stub::*` (11); tests/error_injection.rs; tests/check_flow.rs;
  `session::tests::stub::cannot_check_after_a_collision_restarts_at_the_normal_minimum` (changed 2026-10-10 by
  e87b296: now `cannot_check_after_a_collision_keeps_99_rolls`, plus `the_99_roll_minimum_ends_at_a_passed_check`,
  so 12 stub tests) and
  `collision_evidence_wipes_and_restart_asks_for_99`; `session::tests::the_read_back_gate`,
  `ceremony::every_export_fails_before_read_back`, tests/panic_wipe.rs and tests/no_panic.rs.
- Group 10: the binaries listed above; tests/vectors.rs stays unticked (owner item; ticked 2026-10-10 after owner
  item 9).
- Group 11, the scan: `--selftest` 233 passed under sh and dash (the 24 artifact cases are pasted below).
- Group 12, canaries: 54 checks, all as intended (below); CLAUDE.md Commands: cfdb24a.
- Verification: source substitution (tests/source_substitution.rs, the Pi and phone sessions); pipe width
  (`pool::tests::every_bit_of_the_os_record_reaches_d`, `seed::tests::every_bit_of_d_reaches_c_and_e`,
  `every_bit_of_e_reaches_the_words`); error injection (tests/error_injection.rs, every KatId at new and restart and
  through each free function's twin); trybuild (23 fixtures); go-ahead (`seal::check::tests::*`, tests/check_flow.rs,
  tests/kcr.rs, `ur::tests::decoder_negatives`); snapshot tampering (`seal::snapshot::tests::every_snapshot_case`,
  `every_header_bit_flip_and_truncation_fails`, tests/kcr_release.rs); dice-only against Coldcard
  (`seed::tests::dice_only_matches_coldcard`, `vectors::rolls_json_through_dice_only_sessions`, verify.py check 4);
  braille (`braille::tests::six_sample_inserts`, the 279 and 49 tests, `every_blank_face_slip_is_caught`, check 8);
  watch-only (`descriptor::tests::*`, `seed::tests::bip84_fingerprint_and_first_address`, check 9); secrets never
  printed (tests/no_secret_text.rs, tests/panic_wipe.rs, tests/no_panic.rs); line coverage (below).

**verify.py --selftest** (both Pythons print the same 11 lines, then "selftest passed: 11 checks"):

```text
ok   seal known answers (CLAUDE.md vector 1, project vectors 2 and 3)
ok   vectors/seal.json matches regenerated output
ok   vectors/SOURCES.md hashes and coverage
ok   Coldcard's own scripts on every dice-only case (rolls.json, keepcrypt.json)
ok   vectors/kat.json: SHA and HMAC values recomputed, file matches regenerated output, pinned entries and Ed25519 digest
ok   vectors/keepcrypt.json: embedded BIP39 list and encoder, file matches regenerated output, pinned answers, ...
ok   SP 800-90B health-test cutoffs: Table 2 reproduced exactly, RCT 6 and APT 62 at H = 4
ok   vectors/braille.json: pinned cells, inserts and text, the docs' counts recounted from the list and found in ...
ok   vectors/watchonly.json: RIPEMD-160, CRC-32, dCBOR, Bytewords, UR, BIP-380 and NFKD against the standard ...
ok   vectors/kcr.json: Ed25519 against RFC 8032 TEST 1-3 and kat.json, the docs' snapshot and proof figures, ...
ok   vectors/backup.json: scrypt against hashlib, all 26 CCTV scrypt files through this reader, file matches ...
```

**Coverage.** `cargo llvm-cov --locked -p keepcrypt-core --features test-sources --no-cfg-coverage
--fail-under-lines 95 --summary-only`, cargo-llvm-cov 0.9.1, exit 0 in 63 s:

```text
TOTAL   regions 15763, missed 493, 96.87%   functions 960, missed 36, 96.25%   lines 8248, missed 215, 97.39%
lowest by lines: seal/crockford.rs 73.58% (106, 28 missed)   backup.rs 93.59%   ur.rs 94.72%   pool.rs 94.95%
```

Nothing is excluded: `grep -rn 'coverage(off)\|cfg(coverage' core/` finds nothing, and the CI job's path check
(commit 27) passes on core/src and fails on a planted `core/src/x/tests/a.rs` and `core/src/foo_tests.rs`.

**The KAT list** (`KatId::ALL`, the order a full suite runs; `self_test`, `Session::new` and `Wiped::restart` run all
15; `hwrng_boot_test` runs Health, `seal_from_mnemonic` Seal, the three registry functions Ed25519 then Merkle, and
`decrypt_backup` Age):

```text
Sha256         NIST empty, "abc", two-block              Braille   SHA-256 of the canonical table text; "2026" in cells
Sha512         NIST empty, "abc", two-block              Bip84     abandon: fingerprint, xpub, first address, receive
Hmac           RFC 4231 case 2, both HMAC crates                   checksum and UR, from the S the Seal group checks
Bip39Wordlist  the list's SHA-256 is 2f5eed53...         Seal      S from the abandon words (PBKDF2), then code, T,
Bip39          24 entropy/mnemonic pairs, 2 PBKDF2 seeds           Seal ID and its braille caption
Health         stuck stream fails RCT, alternating APT,  GoAhead   CF94-BCAJ; a wrong n fails
               each at its pinned sample; clean passes   Ed25519   RFC 8032 TEST 1 accepted; one flipped bit refused
Pool           one OS record gives its pinned D          Merkle    a leaf, a node, vector 1's 20-level path
Seed           C, a mixed E, dice-only "123456"          Age       CCTV armor_scrypt decrypts; the writer rebuilds scrypt
                                                                   and armor_scrypt; wrong passphrase refused; work
                                                                   factor 23 refused before scrypt
```

Static cost bound of a full run (kat.rs header, pinned by `kat::tests`): 3 PBKDF2-2048 (2 Bip39, 1 Seal), 3 scrypt
at log2 N 10 (1 MiB each, Age), 2 Ed25519 verifies, one 20-level Merkle path and never a full bucket root, 2,064
Health samples; at most 1 s on a Pi Zero is the plan's estimate, for M4 to measure. Host timing, 100 calls of
`self_test()` in a scratch copy of the workspace (an uncommitted example, timed with `/usr/bin/time -p`, three runs
each): 0.62-0.64 s in the dev profile (core at opt-level 0, dependencies at 3), so 6.3 ms per suite; 0.54 s in
release, 5.4 ms per suite.

**Release-artifact scan, local** (commit 26; the cross job runs it for all six targets in CI). Default features,
release rlib and probe, Xcode 27.0 for iOS:

```text
target/aarch64-apple-ios/release/libkeepcrypt_core.rlib: 4047016 bytes
target/aarch64-apple-ios/release/examples/release_probe: 3558944 bytes
banned-api-check --artifact aarch64-apple-ios: clean, 2 file(s): no marker, no test key, no other RNG symbol;
  _CCRandomGenerateBytes imported by all 1 object or linked file(s) (1 archive(s), which need no import)
target/aarch64-apple-ios-sim/release/libkeepcrypt_core.rlib: 4039176 bytes
target/aarch64-apple-ios-sim/release/examples/release_probe: 3553728 bytes
banned-api-check --artifact aarch64-apple-ios-sim: clean, 2 file(s): ... _CCRandomGenerateBytes imported by all 1 ...
```

The Pi (`arm-unknown-linux-gnueabihf`) and Android legs need the ARM gcc and the NDK, which this Mac does not have;
their first scan is the CI run after the push.

**Both positive controls** (canaries.sh builds these for the host; the same builds by hand, paths shortened to
`target/canary-probe/aarch64-apple-darwin/release/`):

```text
== features: default (control)
banned-api-check --artifact aarch64-apple-darwin: clean, 2 file(s): no marker, no test key, no other RNG symbol;
  _getentropy imported by all 1 object or linked file(s) (1 archive(s), which need no import)    scan exit 0, probe exit 0
== features: test-registry
Marker: libkeepcrypt_core.rlib: KC_TEST_REGISTRY_DO_NOT_SHIP
TestKey: libkeepcrypt_core.rlib: the test registry public key 42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
Marker: examples/release_probe: KC_TEST_REGISTRY_DO_NOT_SHIP
TestKey: examples/release_probe: the test registry public key 42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
banned-api-check --artifact aarch64-apple-darwin: 4 hit(s) in 2 file(s)                          scan exit 1, probe exit 0
== features: test-sources
Marker: libkeepcrypt_core.rlib: KC_TEST_SOURCE_DO_NOT_SHIP
Marker: libkeepcrypt_core.rlib: KC_TEST_REGISTRY_DO_NOT_SHIP
TestKey: libkeepcrypt_core.rlib: the test registry public key 42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
Marker: examples/release_probe: KC_TEST_SOURCE_DO_NOT_SHIP
Marker: examples/release_probe: KC_TEST_REGISTRY_DO_NOT_SHIP
TestKey: examples/release_probe: the test registry public key 42e9fa0e206d4bdf410f987ac7ded54fb02fb49ef277cc425d5fdfdb72c3b94b
banned-api-check --artifact aarch64-apple-darwin: 6 hit(s) in 2 file(s)                          scan exit 1, probe exit 0
```

The test-registry build holds no stub marker; its probe exits 0, so the probe's embedded snapshot verifies under the
test key, and the default probe exits 0 with `NoRegistryKey`.

**The scan's selftest** (24 artifact cases of the 233; temp paths shortened to `<tmp>/`):

```text
PASS artifact-test-key-is-kcr-json-test-registry-key
PASS artifact-aarch64-linux-android-clean-object -> exit 0
PASS artifact-aarch64-linux-android-arc4random-import -> exit 1; Symbol: <tmp>/...-arc4random.o: undefined arc4random
PASS artifact-aarch64-linux-android-missing-os-import -> exit 1; OSImport: <tmp>/...-no-os-import.o: no undefined getrandom, ...
PASS artifact-aarch64-linux-android-getentropy-import -> exit 1; Symbol: <tmp>/...-getentropy.o: undefined getentropy
PASS artifact-aarch64-linux-android-rand-crate-symbols -> exit 1; Symbol: ... rand::backends::use_file::fill_inner;
     Symbol: ... rand::rngs::next_u32
PASS artifact-aarch64-linux-android-getrandom-fallback-symbol -> exit 1; Symbol: ...: getrandom's fallback
     getrandom::backends::use_file::fill_inner
PASS artifact-aarch64-linux-android-archive-needs-no-import -> exit 0
PASS artifact-aarch64-linux-android-archive-member-arc4random -> exit 1; Symbol: <tmp>/...-arc4random.rlib: undefined arc4random
PASS artifact-aarch64-apple-ios-clean-object -> exit 0
PASS artifact-aarch64-apple-ios-arc4random-import -> exit 1; Symbol: ...: undefined _arc4random
PASS artifact-aarch64-apple-ios-missing-os-import -> exit 1; OSImport: ...: no undefined _CCRandomGenerateBytes, ...
PASS artifact-aarch64-apple-ios-getentropy-allowed -> exit 0
PASS artifact-aarch64-apple-ios-rand-crate-symbols -> exit 1; (the same two rand:: symbols)
PASS artifact-aarch64-apple-ios-getrandom-fallback-symbol -> exit 1; Symbol: ...: getrandom's fallback ...
PASS artifact-aarch64-apple-ios-archive-needs-no-import -> exit 0
PASS artifact-aarch64-apple-ios-archive-member-arc4random -> exit 1; Symbol: ...: undefined _arc4random
PASS artifact-marker-source-text -> exit 1; Format: testdata/artifact/marker-source.txt: ...; Marker: ...: KC_TEST_SOURCE_DO_NOT_SHIP
PASS artifact-marker-registry-text -> exit 1; Format: ...; Marker: ...: KC_TEST_REGISTRY_DO_NOT_SHIP
PASS artifact-test-key-bytes -> exit 1; Format: <tmp>/test-key.bin: ...; TestKey: <tmp>/test-key.bin: the test registry public key ...
PASS artifact-two-files -> exit 1; (only the marker file's two hits)
PASS artifact-error-unknown-target -> exit 2
PASS artifact-error-missing-file -> exit 2
PASS artifact-error-no-file -> exit 2
selftest: 233 passed, 0 failed
```

**Canaries** (54 checks; the 14 new at commit 26, after the 40 before it):

```text
PASS: graph: no serde in core's normal or build graph; getrandom's only dependent is core; dalek features pinned
PASS: graph-pins failed as intended
PASS: vectors-tamper-seal.json failed as intended        (and kat, keepcrypt, braille, watchonly, kcr, backup.json,
                                                          age/age_cli_written.json: 8 in all)
PASS: release-probe-default: the scan is clean and the probe runs (control)
PASS: release-probe-test-registry failed as intended
PASS: release-probe-test-registry: the probe verifies its snapshot under the test key
PASS: release-probe-test-sources failed as intended
PASS: all 54 checks ran
```

**age-interop, local** (Homebrew age 1.3.2, the only CLI on this Mac; the CI job runs Ubuntu's 1.1.1 after the
push), `python3 scripts/age-interop.py --core`, exit 0 in 13.5 s:

```text
age-interop: v1.3.2
age-interop: ok: age -> KeepCrypt and KeepCrypt -> age at work factor 18, armored and binary; wrong passphrases
  refused by both; age_cli_written.json decrypted by both
age-interop: ok: age decrypted all 12 backup.json age files the readers accept, and also refused 15 of the 15
  armor cases they refuse
age-interop: ok: core read age's files (decrypt_backup), age read core's fresh work-factor-18 backups, and age
  refused a wrong passphrase
```

**The one-time SeedBook PDF check** is recorded above ("M1: one-time SeedBook PDF check", review fix after commit
15): 2,048 printed numbers equal 1-2048, 0 rows whose capitals differ from the list, the six samples and the cover
match, problems: 0.

**The CI workflow** (commit 27) is checked locally only: `ruby -ryaml` loads it (9 jobs: changes, lint, test,
supply-chain, gates, verifier-py39, coverage, age-interop, and cross with 6 legs, so 14 check runs). The changes
script gives `entropy=true` for HEAD~1..HEAD and for an unreadable range, and `entropy=false` for the README-only
commit b4e8e47 against its parent (a scratch worktree). The first real run comes after the push. Those three ranges
missed three ways the changes job failed open, fixed after 29; see "M1: review fixes after 29".

**Q12 ruleset: not created.** It changes the GitHub repo's settings, and the owner asked to be asked once more
right before it is created ("Needed before M1"); that go-ahead has not been given, so it is an owner item below.
`main` stays unprotected until then. build-plan.md's two-approval rule ("Review": CODEOWNERS requires two approvals)
is unmet while one account (`bitwilll`) opens and merges every PR. (Created 2026-10-10 after the owner's yes: ruleset
24833307, under "M1: the owner's answers applied".)

**Unticked, and what each waits for** (at cfdb24a; on 2026-10-10 the owner's answers closed every owner wait below,
and what still waits is listed under "M1: the owner's answers applied"):
- Group 0, branch protection: the owner's go-ahead for the Q12 ruleset.
- Group 4 `seed.rs`, group 6 `crypto-account` and the export, group 7 `seal/crockford.rs` and derivation, group 8
  `backup/age.rs`: built and tested as above, but each records library residuals "for the owner's review (not yet
  accepted)".
- Group 4 `seed.rs` also, and group 10 `tests/vectors.rs`, and Verification "All vectors pass": the owner item on
  tests/vectors.rs and the 16 of 24 BIP39 seeds.
- Group 5 braille vectors and KAT group Braille: Q15.
- Group 8 vectors, the Backup API and "Check a backup", and Verification "Backup": the age 1.1.1 files (the age
  1.3.2 substitution) and the CI age-interop run against Ubuntu's 1.1.1.
- Group 11 `release_probe.rs`, group 12 CI jobs and coverage, group 13 Review, and Verification "The release
  artifact scan is clean on all six targets" and "Clean ... CI is green": the first CI run after the push (the Pi
  and Android scans, the coverage and age-interop jobs, the changes job), and the Q12 ruleset or its deferral.

### M1: review fixes after 29 (2026-10-10)
The review of commits 26-29 reported ten findings: six defects (three of them reported more than once) and one
missing record. Each was reproduced before its fix and re-run after, in scratch directories outside the repo.

**The changes job (Q12), 216b0a1.** It matched `^(Entropy/|...)` against `git diff --name-only` and so set
`entropy=false`, which skips every other job (GitHub counts that as passing), in three cases. Rename detection lists
only a moved file's new path. `core.quotePath` prints a non-ASCII name in quotes. And `printf | grep -q` under
`-eo pipefail` fails on a long list: grep exits at its first match, printf dies of SIGPIPE, and pipefail makes the
`if` false. The step now runs `git diff --quiet --no-renames "$base" HEAD -- Entropy/ .github/workflows/entropy-ci.yml`
from the repo root. Exit 0 means false, 1 means true, and anything else runs every job. Run steps start in Entropy/,
where those pathspecs would match nothing. The root comes from a plain assignment, so a failing `rev-parse` fails the
step and does not carry on in Entropy/; outside a repo the step exits 128. The name list (`--no-renames`, quotePath
off) only feeds the log. The step was extracted with `ruby -ryaml` from 98e3fe5 (before) and de93cbc (after) and run
as GitHub runs `shell: bash` (`bash --noprofile --norc -eo pipefail`, starting in Entropy/), on a scratch repo. The
PR cases are `--no-ff` merges standing in for the merge ref (EVENT=pull_request, base HEAD^1); the push cases set
BEFORE:

```text
case                                            before  after
pr:entropy-edit                                 true    true
pr:readme-only                                  false   false
pr:workflow-edit                                true    true
pr:other-workflow                               false   false
pr:lookalike-paths (Entropyx.txt, ...yml.bak)   false   false
pr:delete-gate-file                             true    true
pr:rename-out-deny (-> deny.toml at the root)  false   true
pr:rename-out-canaries (-> attic/)              false   true
pr:rename-out-workflow                          false   true
pr:rename-into-entropy                          true    true
pr:rename-nonascii (canaries.sh -> canariés.sh) false   true
pr:add-nonascii (Entropy/café.md)               false   true
pr:mode-only (chmod +x)                         true    true
pr:large-with-entropy (+3,000 files, zz-bulk/)  false   true
pr:large-without-entropy (3,000 files)          false   false
push:entropy-edit                               true    true
push:readme-only                                false   false
push:rename-out                                 false   true
push:large-with-entropy (+1,500 files)          false   true
push:new branch (zero before)                   true    true
push:unknown before (force push)                true    true
push:empty before                               true    true
22 cases: 14 right and 8 wrong before, 22 right after
```

On the real repo (a shared scratch clone), README-only b4e8e47 against its parent still gives `entropy=false`, and
HEAD~1..HEAD at 98e3fe5 gives `true`. The log for a move plus a non-ASCII file now reads `changed: Entropy/café.md`,
`changed: Entropy/deny.toml`, `changed: deny.toml`.

**The coverage path check, de93cbc.** cargo-llvm-cov 0.9.1's default ignore rule (src/report.rs,
`ignore_filename_regex`) also skips any path holding `/rustc/<hex>/` or `/rustc/<x.y.z>/`, anywhere in it. In a
scratch export of 98e3fe5, a module core/src/rustc/cafe/mod.rs held an uncalled function.
`cargo llvm-cov --offline --locked -p keepcrypt-core --lib --no-cfg-coverage --summary-only` gave no row for it
(TOTAL lines 7285, missed 357), while the old check passed (rc=0). Renamed to rustc/plant, it gave
`rustc/plant/mod.rs 6 lines, 6 missed` (TOTAL 7291, 363). The step, extracted the same way, on planted trees:

```text
before: rustc/cafe rc=0   rustc/1.2.3 rc=0   rustc/plant rc=0   tests/ rc=1   foo_tests.rs rc=1   clean rc=0
after:  FAIL on rustc/cafe, rustc/1.2.3, rustc/0abc/x, tests/, examples/a/, foo_tests.rs, foo-tests.rs, a/tests.rs
        pass on clean, rustc/plant, rustc/1.2 and xrustc/cafe (the tool keeps those too), and on the real core/src
```

A report-against-tree comparison, which the review offered instead, was not added. A file with no function never
gets a row: that run had 30 rows for 32 files, missing lib.rs (no function) and source/stub.rs (test-sources only).
So the comparison would need its own list of exempt files.

**The artifact scan, d283a36.** Fixtures were built with the pinned rustc for aarch64-linux-android (`--emit obj`):

```text
libc_r.o (llvm-nm -u: drand48_r getrandom lrand48_r rand random_r seed48)
  before: Symbol: undefined rand                                                1 hit
  after:  undefined drand48_r, lrand48_r, rand, random_r, seed48                5 hits
fixture.rs built as each of deny.toml's 13 crate names
  before: rand 2 hits; rand_pcg, rand_xorshift, rand_hc, rand_isaac, oorandom, nanorand, tinyrand, turborand clean
  after:  2 hits under every name
llvm-ar rcsT thin.rlib m.o (m.o: a #[used] static holding KC_TEST_SOURCE_DO_NOT_SHIP)
  before: clean, exit 0 ("1 archive(s), which need no import"); the same as a normal archive: Marker hit, exit 1
  after:  Format: thin.rlib: a thin archive, which holds its members' paths, not their bytes   exit 1
```

The selftest grows from 233 to 250 cases (233 is a run of 98e3fe5's tree). The new cases: the 13 names checked
against deny.toml's rule-1 block (`PASS artifact-rng-crates-are-deny-toml-rule-1 (13 names)`), the libc case and a
thin archive on both targets, and the other 12 crate names on Android. Each rule was then reverted in a scratch
copy, and each revert fails its own cases:

```text
scan list drops turborand           FAIL artifact-rng-crates-are-deny-toml-rule-1          248 passed, 1 failed
deny.toml's block gains a name      FAIL artifact-rng-crates-are-deny-toml-rule-1          249 passed, 1 failed
the old undefined-symbol pattern    FAIL ...-libc-reentrant-draws on both targets          248 passed, 2 failed
the old 5-crate list                FAIL the 8 crate cases outside the old list            242 passed, 8 failed
thin archive back as an archive     FAIL ...-thin-archive on both targets                  248 passed, 2 failed
```

The real artifacts are still clean under the new rules. The iOS release rlib and probe (`aarch64-apple-ios`,
`aarch64-apple-ios-sim`) scan clean, with `_CCRandomGenerateBytes` imported. In canaries.sh the host default probe
scans clean, and both positive controls still fail as intended (54 checks). The Pi and Android scans run first in
CI.

**The Pi games' getrandom (record only; open owner item 12, answered (b) on 2026-10-10).** The pin "getrandom's
only dependent is keepcrypt-core" (Q11 (c), commit 26) was run on a copy of the tree whose pi/app/Cargo.toml adds
`getrandom = "0.4.3"`, as pi-firmware.md has the games do. The pin's script, taken from canaries.sh, was run after
`cargo update --offline --workspace`:

```text
unchanged copy:            rc=0
pi/app depends on getrandom: getrandom dependents in Cargo.lock: keepcrypt-core, keepcrypt-pi; needs keepcrypt-core only
                           rc=1
```

The pin is unchanged. The conflict is recorded under "Carried to later milestones" (M3) and as open owner item 12.

**Suite**, before each of the three fix commits (runs on the trees of 98e3fe5 plus the scan change, d283a36 plus
the changes job, and 216b0a1 plus the coverage check), with the same results each time; this file's commit changes
nothing else:

```text
cargo fmt --all --check                                          exit 0
cargo clippy --workspace --all-targets --locked -- -D warnings   exit 0
cargo clippy ... --all-features --locked -- -D warnings          exit 0
cargo test --workspace --locked                                  exit 0  (17 s)
cargo test -p keepcrypt-core --locked --features test-sources    exit 0  (59 s)
cargo deny --locked check                                        exit 0  advisories ok, bans ok, licenses ok, sources ok
cargo audit                                                      exit 0  94 crate dependencies
cargo vet --locked                                               exit 0  Vetting Succeeded (14 fully audited, 76 exempted)
sh scripts/check-path-deps.sh                                    exit 0  clean, 90 packages outside the workspace
sh scripts/banned-api-check.sh                                   exit 0  clean, 161 files scanned
sh scripts/banned-api-check.sh --selftest                        exit 0  selftest: 250 passed, 0 failed
python3 tools/verify/verify.py --selftest                        exit 0  selftest passed: 11 checks
/usr/bin/python3 tools/verify/verify.py --selftest               exit 0  selftest passed: 11 checks
sh scripts/canaries.sh                                           exit 0  PASS: all 54 checks ran
```

The workflow loads with `ruby -ryaml` at every step (9 jobs, 6 cross legs; every job but changes needs it). As
before, the CI run itself comes after the push.

### M1: open owner items (2026-10-10; all 12 answered 2026-10-10)
Nothing below has been acted on beyond recording it. Each needs the owner's answer before the M1 gate. (Answered and
applied on 2026-10-10: see the next subsection, "M1: the owner's answers".)
1. **Q12 ruleset (needs an explicit go-ahead).** A ruleset on `main` scoped to `Entropy/**`: require a pull request
   and these checks: `changes (Entropy/ or this workflow)`, `lint (fmt, clippy)`, `test`, `supply-chain (deny, audit,
   vet)`, `gates (banned APIs, verifier, canaries)`, `verifier (python 3.9)`, `coverage (core, 95% of lines)`,
   `age-interop (age 1.1.1)` and the six `cross (<target>)` legs; 0 approvals while one account opens and merges
   every PR. The changes job must be required too: if it fails, the jobs that need it are skipped, and GitHub counts
   skipped as passing. Created with `gh api repos/bitwilll/keepcrypt/rulesets` only after the go-ahead, and its
   output then goes under Review. (Created 2026-10-10: ruleset 24833307.)
2. **Q13 (a)-(e) and Q14 (a)-(b):** the agent applied the standing approval to both; please confirm explicitly
   ("Raised by the review of commits 2-5").
3. **Q15:** the Braille table text and its digest `fd75c236...` in place of `41f0e259...`, and the Braille KAT's
   reworded proof ("Raised by the review of commits 11-15").
4. **The 99-roll question:** 99 rolls give 255.9 bits, not 256 (group 4, `dice.rs`). Keep 99 for 24 words (and after
   a collision), or move to 100 rolls (258.5 bits), a CLAUDE.md "Dice quota" and design.md change. Until answered,
   99 stands.
5. **Cannot check after a collision:** the restart after a collision needs 99 rolls; if that new session's check
   then ends in "Cannot check", the next restart uses the normal minimum (50 for 12 words), as
   seal-watchonly-braille.md "Add fresh entropy" reads ("After 'Cannot check', the next ceremony uses the normal
   minimum"), pinned by `cannot_check_after_a_collision_restarts_at_the_normal_minimum`. Confirm, or keep 99 until a
   check passes after a collision. (Changed 2026-10-10, answered "keep 99 until a check passes": dc53b8f changed "Add
   fresh entropy", and e87b296 replaced that test with `cannot_check_after_a_collision_keeps_99_rolls`.)
6. **Library residuals (accepted 2026-10-10 as an M7 audit note; Q1 (iii) had accepted scrypt's working buffer):**
   - BIP32 and BIP39 (group 4): rust-bitcoin's copies of the parent key in `derive_priv`, the HMAC state and output
     in its `ckd_priv` and `new_master`, secp256k1's tweak temporaries, and the moved-from S of bip39's
     `to_seed_normalized` stay on the stack unwiped;
   - BIP39 passphrase NFKD (group 6): unicode-normalization 0.1.25's pending-character buffer, left unwiped on the
     stack by both NFKD passes and, for long decompositions, moved to the heap and freed unwiped;
   - the xpub (group 6): about six freed heap copies while the export is built (public-key data);
   - hmac 0.13 (group 7): the padded key block of the seal's HMAC-SHA256 key S, also in scrypt's PBKDF2 steps keyed
     by the backup passphrase (group 8);
   - HKDF (group 8): copies of the pseudorandom key derived from the file key;
   - Poly1305 (group 8): the one-time key r and s stay in the dropped cipher state, because poly1305 resolves without
     its `zeroize` feature; wiping them needs a new direct dependency edge. (Changed 2026-10-10: b4871b9 adds that
     edge, so r and s are wiped on drop, except the backends' stack temporaries: the soft backend's in `State::new`
     and `finalize`, and, on x86_64-linux-android, the AVX2 backend's.)
7. **The age 1.3.2 vectors:** approve `vectors/age/age_cli_written.json` as written with Homebrew age 1.3.2, or have
   it regenerated with Ubuntu's 1.1.1 (for example in the CI job) and committed in a `verify:` commit ("Raised by
   the review of commits 19-21").
8. **The scrypt upstream issue (Q1 (iii)):** not filed. Filing posts in public, so it waits for the owner to file it
   or to say go ahead; then its link goes here. (Filed 2026-10-10 after the owner's yes:
   https://github.com/RustCrypto/password-hashes/issues/938.)
9. **tests/vectors.rs and the 16 of 24 BIP39 seeds:** approve as built (the secret-holding sets run as unit tests;
   core derives the 16 12- and 24-word TREZOR seeds, not the 8 18-word ones), or ask for a test-only constructor
   and a stdlib PBKDF2 check in verify.py ("Raised by the review of commits 22-25").
10. **The Public API sketch (build-plan.md) against the built API:** `credited_bits()`, `required_bits()` and
    `hw_bytes_tested()` return u64 (the sketch: u32); `Wiped::collision_report(&self)` returns
    `Option<&CollisionReport>` (the sketch: an owned `Option<CollisionReport>`); the dates are `RegistryDate` with
    `Freshness`; `VerifiedProof::lookup`, and `number()` and `entry_count()` on both verified types, are public
    additions. Approve a docs-only commit that aligns the sketch, or keep it as a sketch. (Done 2026-10-10 in
    62e2e5e: the sketch now gives u64, `Option<&CollisionReport>`, `RegistryDate` and the public additions.)
11. **cargo-vet exemptions to approve (33 new in M1):**
    - safe-to-deploy (19): aead 0.6.1, base64ct 1.8.3, chacha20 0.10.2, chacha20poly1305 0.11.0, cipher 0.5.2,
      cmov 0.5.4, ctutils 0.4.2, curve25519-dalek 5.0.0, curve25519-dalek-derive 0.1.1, ed25519 3.0.0,
      ed25519-dalek 3.0.0, hkdf 0.13.0, hmac 0.13.0, pbkdf2 0.13.0, poly1305 0.9.1, salsa20 0.11.0, scrypt 0.12.0,
      signature 3.0.0, universal-hash 0.6.1;
    - safe-to-run, dev only (14): glob 0.3.4, hashbrown 0.17.1, indexmap 2.14.2, itoa 1.0.18, memchr 2.8.3,
      serde_json 1.0.151, target-tuple 1.0.2, toml 1.1.6+spec-1.1.0, toml_parser 1.1.3+spec-1.1.0,
      toml_writer 1.1.2+spec-1.1.0, trybuild 1.0.121, windows-sys 0.61.2, winnow 1.0.4, zmij 1.0.23.
    The other 11 new crates pass on imported audits (listed under group 1's proof above).
12. **The Pi games' getrandom (before M3; raised by the review after 29).** CLAUDE.md rule 1 ("Games use their own
    separate `getrandom` calls"), pi-firmware.md (the `games` row and "Game randomness") and banned-api-check.sh's
    Rule1 exemption for pi/app/src/games all expect pi/app to call getrandom. The graph pin approved in Q11 (c) and
    added in commit 26 allows no getrandom dependent except keepcrypt-core. With `getrandom = "0.4.3"` in
    pi/app/Cargo.toml it fails: "getrandom dependents in Cargo.lock: keepcrypt-core, keepcrypt-pi; needs
    keepcrypt-core only". Choose one:
    - (a) allow keepcrypt-pi as a second dependent, which is a reviewed change to the pin and its mutation canary;
    - (b) give the games bytes through a core API that makes its own getrandom call and never touches the pool, as
      "Inputs from M0" proposes for the phone games. Rule 1, pi-firmware.md and the Rule1 exemption then change to
      match.

    Nothing changes until then. (Answered 2026-10-10: (b), applied in 73abaea and 2441d39.)

### M1: the owner's answers (2026-10-10)
The lead put the 12 items above to the owner in one message, with a recommendation for each, and wrote: "You can
reply "approve all", but items 1 and 8 act on GitHub, so I'll only do those with your explicit yes." The owner
answered, verbatim: "approve all, yes to 1 and 8". So each recommendation below, as put to the owner, is the owner's
decision, and items 1 and 8 have the explicit yes they needed. The proof for each commit is under "M1: the owner's
answers applied".
1. **Branch protection.** Put: create the ruleset on `main` that requires a PR and the Entropy checks, with 0
   approvals for now; it changes repo settings, so it needs a yes. Yes given. Done: ruleset 24833307, active on
   `refs/heads/main`. Plan group 0's branch-protection item is ticked.
2. **Q13 and Q14.** Put: confirm the five doc fixes and the two gate tightenings already applied. Confirmed: Q13
   (a)-(e) (c40a2e3) and Q14 (a)-(b) (f732c98) stand; nothing is reverted.
3. **Q15.** Put: approve the braille-table hash `fd75c236...`. Approved, with the table-text definition and the
   reworded proof. Group 5's vectors and its Braille KAT are ticked.
4. **99 dice rolls give 255.9 bits.** Put: keep 99 (Coldcard-compatible, and the device adds its own 256 bits), and
   change the docs to "about 256". Done: 012c8db (design.md). 6ba465c says under the seed-pipeline figure that its
   "99 give 256" rounds up; redrawing the figure is new item 13.
5. **"Cannot check" after a collision.** Put: keep 99 until a check passes, since a device that just collided is
   suspect; a small code and doc change. Done: dc53b8f (seal-watchonly-braille.md "Add fresh entropy",
   build-plan.md's `Wiped::restart` comment) and e87b296 (core and its tests); 34beea2 gives the Pi and phone flows
   the Cannot check branch, whose "Start again" restarts through `Wiped::restart`. Any other wipe of the restarted
   session still ends the minimum, which the docs now say; that is new item 14.
6. **Library residuals.** Put: accept the key copies inside rust-bitcoin, bip39, hmac, HKDF and Poly1305 that core
   cannot wipe as an M7 audit note, plus switch on Poly1305's wipe feature. Accepted; the note is under "Notes for
   later milestones". 0ac7394 names poly1305 in build-plan.md, b4871b9 adds the direct edge with `zeroize`, and
   7c46d93 pins the feature on each target. The residual records in groups 4, 6, 7 and 8 now say accepted, so
   core/src/backup/age.rs's citation of this item holds. The message put to the owner did not name two entries of
   the full list: unicode-normalization's pending-character buffer, which holds the BIP39 passphrase's NFKD
   (secret), and the xpub's freed heap copies (public). The M1 gate report names both, for the owner to confirm.
7. **The age interop files.** Put: approve the files made with age 1.3.2; CI checks Ubuntu's 1.1.1 in both
   directions. Approved.
8. **The scrypt upstream issue.** Put: file it yourself, or give a yes to post it under the owner's account. Yes
   given. Filed as https://github.com/RustCrypto/password-hashes/issues/938 ("scrypt: zeroize the B, V and T buffers
   before freeing them").
9. **BIP39 vectors.** Put: approve; core runs 16 of the 24 published vectors, and the other 8 are 18-word seeds,
   which KeepCrypt does not support. Approved as built, both (a) the placement and (b) the 16 of 24. Group 10's
   tests/vectors.rs and Verification "All vectors pass" are ticked.
10. **The API sketch in build-plan.md.** Put: a docs-only commit to match the built API, such as u64 counters and
    borrowed reports. Done: 62e2e5e.
11. **33 cargo-vet exemptions.** Put: approve the 19 for device crates and the 14 for dev-only crates. Approved;
    `cargo vet --locked` still gives "14 fully audited, 76 exempted".
12. **The Pi games' randomness.** Put: (b), the games get bytes from a small core API that never touches the entropy
    pool and also serves the phone games; the alternative (a) lets pi/app call getrandom itself. (b) chosen. Done:
    73abaea (CLAUDE.md rule 1, pi-firmware.md, mobile-apps.md, seal-watchonly-braille.md, and the banned-API gate
    loses its pi/app/src/games exemption) and 2441d39 (build-plan.md's `source` row and sketch). M3 builds the call
    ("Notes for later milestones"); the graph pin stays.

### M1: new open owner items (2026-10-10; low, not blocking the M1 gate)
Raised by the reviews of the owner-item commits; also listed under "Open questions for the owner".
13. **The seed-pipeline figure.** `docs/img/seed-pipeline.png` still reads "50 rolls give 129 bits; 99 give 256".
    The repo holds no source for it (only the starter commit 91dc31a touched it). 6ba465c notes the rounding in the
    sentence under the figure. A redraw, so the box reads "99 give about 256 (255.9)", needs the owner's source file
    or approval to redraw it.
14. **The 99-roll minimum after a wipe (raised by the security review).** Only a `Wiped` carries the 99-roll minimum
    after a collision, and only a check leaves one (`Wiped::from_check`). So an error, the Pi's idle wipe, the
    phones' background or screenshot wipe, or an app kill in the restarted session leads to `Session::new` at the
    normal minimum: 50 rolls for 12 words (24 words need 99 anyway). seal-watchonly-braille.md "Add fresh entropy"
    now states that exception (dc53b8f). Recommended: in M3, add a core exit on the pre-Ready states that wipes and
    returns a `Wiped` keeping the flag, for the shells' timeout and capture wipes. That changes the typestate API
    (rule 6 fixtures), so it needs the owner's approval. Power-off can never keep the flag, because nothing is
    persisted (rule 8). Otherwise: keep the documented exception. Answered 2026-10-11 (M3 Q26 (C)): the borrowing
    `Wiped::restart` (7299e27; seal-watchonly-braille.md in c306bc2); see "Open questions for the owner".

### M1: the owner's answers applied (2026-10-10)
**CI on 4733e4a** (run https://github.com/bitwilll/keepcrypt/actions/runs/38033374724, PR #4; the first run with
commit 27's coverage, scan and age-interop jobs): 13 of the 14 check runs passed, and `age-interop (age 1.1.1)`
failed:

```text
age-interop: 1.1.1
FAIL backup.json age_files abandon-12-whitespace: the readers accept it, age exits 1, plaintext differs
FAIL backup.json age_files abandon-12-leading-1024: the readers accept it, age exits 1, plaintext differs
```

The same run's first Pi and Android scans, and its coverage job (core has changed since, so CI on 34beea2 proves
them again):

```text
cross (arm-unknown-linux-gnueabihf)  clean, 2 file(s): no marker, no test key, no other RNG symbol; getrandom imported
cross (aarch64-linux-android)        clean, 2 file(s): ... getrandom imported
cross (armv7-linux-androideabi)      clean, 2 file(s): ... getrandom imported
cross (x86_64-linux-android)         clean, 2 file(s): ... getrandom imported
cross (aarch64-apple-ios)            clean, 2 file(s): ... _CCRandomGenerateBytes imported
cross (aarch64-apple-ios-sim)        clean, 2 file(s): ... _CCRandomGenerateBytes imported
coverage                             TOTAL regions 96.87%, functions 96.25%, lines 8248, missed 215, 97.39%
```

Root cause: age 1.1.1's CLI reads armor only when BEGIN is at byte 0 (v1.1.1 cmd/age/age.go:
`rr.Peek(len(armor.Header))`). age 1.3.0 and later skip up to 1,024 bytes of leading whitespace (v1.3.1
cmd/age/age.go lines 495-497); 1.2.0 and 1.2.1 still read armor only at byte 0. The readers had copied the 1.3 rule.
Fixed in d8b5d25: both readers refuse any whitespace before BEGIN, which C2SP age allows (recorded under plan group
8, `backup/armor.rs`). Without 1.1.1 on this Mac, a scratch check that every accepted file starts at byte 0 with
BEGIN or the version line passes on the new backup.json and fails on 4733e4a's with exactly the two files CI named:

```text
new backup.json:  all 11 age_files start with BEGIN or the version line at byte 0
4733e4a's:        AssertionError: ['abandon-12-whitespace', 'abandon-12-leading-1024']
```

**The ruleset (owner item 1).** Created on 2026-10-10 at 13:18:44 +05:30 with `gh api` (POST
repos/bitwilll/keepcrypt/rulesets). Re-read with `gh api repos/bitwilll/keepcrypt/rulesets/24833307`:

```text
id 24833307  name "main: pull requests and Entropy CI"  target branch  enforcement active  source bitwilll/keepcrypt
conditions   ref_name include ["refs/heads/main"], exclude []
bypass       bypass_actors [], current_user_can_bypass "never"
rules        deletion
             non_fast_forward
             pull_request: required_approving_review_count 0, require_code_owner_review false,
               dismiss_stale_reviews_on_push false, require_last_push_approval false,
               required_review_thread_resolution false, require_extra_approval_for_unattributed_changes true,
               allowed_merge_methods [merge, squash, rebase], required_reviewers [] (the last three are server
               defaults; the request set none of them)
             required_status_checks: strict false, do_not_enforce_on_create false, 14 contexts, each
               integration_id 15368 (GitHub Actions):
               changes (Entropy/ or this workflow) | lint (fmt, clippy) | test | supply-chain (deny, audit, vet) |
               gates (banned APIs, verifier, canaries) | verifier (python 3.9) | coverage (core, 95% of lines) |
               age-interop (age 1.1.1) | cross (aarch64-apple-ios) | cross (aarch64-apple-ios-sim) |
               cross (aarch64-linux-android) | cross (arm-unknown-linux-gnueabihf) |
               cross (armv7-linux-androideabi) | cross (x86_64-linux-android)
```

With no bypass actors, even the owner's direct pushes and web edits to `main` need a PR. The deletion and
force-push rules are the standard pair added with the ruleset; Q12 did not name them. A ruleset cannot limit its
checks to `Entropy/**`, so the changes job skips the other jobs on a PR that does not touch `Entropy/` (Q12).
build-plan.md's two-approval rule stays unmet while one account (`bitwilll`) opens and merges every PR. GitHub's
"Available rules for rulesets" page (read 2026-10-10) says `require_extra_approval_for_unattributed_changes` asks for
one approval more on a Copilot pull request that is not attributed to a person, is on by default, and has no effect
while the ruleset requires 0 approvals. The request body and the API's response stay in the session scratchpad.

**The upstream issue (owner item 8).** https://github.com/RustCrypto/password-hashes/issues/938, "scrypt: zeroize
the B, V and T buffers before freeing them", opened 2026-10-10 07:49 UTC by bitwilll, open. It asks scrypt 0.12.0
(master is the same) to zeroize its `b`, `v` and `t` buffers before they drop, always or behind a `zeroize` feature:
the first block of the freed `v` lets anyone who reads that memory test passphrase guesses for one PBKDF2 iteration
each.

**The 12 commits** (4733e4a..34beea2, oldest first). Each line gives the proof its implementer ran; the whole suite
at 34beea2 is below.

```text
d8b5d25 verify, core: the armor readers refuse whitespace before BEGIN, since age 1.1.1 reads armor only at byte 0
        backup.json regenerated (11 accepted, 44 refused); cargo test --lib backup: 29 passed, 1 ignored; check 11's
        byte-0 assertion fires on a copy with one LF before abandon-12-crlf; age-interop --core (1.3.2) exit 0
dc53b8f docs: after a collision, the 99-roll minimum stays through Cannot check until a check passes
        seal-watchonly-braille.md "Add fresh entropy", build-plan.md's Wiped::restart comment; selftest 11 checks
e87b296 core: Cannot check keeps the checking session's 99-roll flag, so after a collision 99 rolls stay until a check passes
        cannot_check_after_a_collision_keeps_99_rolls and the_99_roll_minimum_ends_at_a_passed_check pass; the
        mutant (false, None) fails both, the mutant (true, None) fails discard_and_restart
0ac7394 docs: build-plan.md names poly1305 among core's crates, only to switch on its zeroize
b4871b9 core: switch on poly1305's zeroize so its one-time key is wiped on drop
        cargo tree -e normal --target T: "poly1305 v0.9.1|zeroize" on all six cross targets; Cargo.lock +2 lines,
        no new package; deny ok, audit ok, vet "14 fully audited, 76 exempted"; canaries 54
012c8db docs: 99 rolls give about 256 bits (255.9), not 256
        design.md only, four places; selftest 11 checks
62e2e5e docs/build-plan.md: align the Public API sketch with the built API
        the sketch checked against every pub item lib.rs re-exports; selftest 11 checks on both Pythons
73abaea rule 1: games get their bytes through core, not their own getrandom (owner item 12 (b))
        banned-api-check --selftest 251 passed; the two new Rule1 fixtures (pi/app/src/games.rs and games/snake.rs)
        pass the old script and are hits under the new one; scan clean, 161 files; canaries 54
7c46d93 scripts/canaries.sh: the poly1305 zeroize pin checks each target on its own, not --target all
        on a copy with zeroize only under cfg(target_os = "linux"): the old pin exits 0, the new one exits 1 for
        the three Android targets, both iOS targets and the host; canaries 54; tree() forced back to --target all
        fails graph-pins
6ba465c docs/design.md: the paragraph under the seed-pipeline figure says the figure's "99 give 256" rounds up
2441d39 docs: build-plan.md places core's game-randomness call in source from M3; the Pi games get the sink, never the session
34beea2 docs: the Pi and phone flows add the Cannot check branch, whose "Start again" restarts through Wiped::restart
        the last three change docs only; check 11 reads build-plan.md, pi-firmware.md and mobile-apps.md
        (checks 8 and 10 read seal-watchonly-braille.md), and verify.py --selftest passes 11 checks at 34beea2
        on both Pythons (suite below)
```

**The three reviews** (spec, security, recompute) of those commits gave 9 findings:
1. Spec, medium: items 5, 6 and 12 (b) looked chosen by reading "approve all", and age.rs cited an "M7 audit note"
   that no record held. The reviewers could not see the lead's message. Each recommendation was put to the owner
   and approved as put ("M1: the owner's answers"), and this record makes age.rs's citation true. Nothing reverted.
2. Spec, low: `docs/img/seed-pipeline.png` still says "99 give 256". Partly fixed in 6ba465c (the sentence under the
   figure); the redraw is new item 13.
3. Spec, low: build-plan.md did not define the game-randomness call, and pi-firmware.md's "games receive only this
   sink" was incomplete. Fixed in 2441d39; the M3 carry is under "Notes for later milestones".
4. Spec, low: neither shell spec had the Cannot check branch, so a shell that called `Session::new` for "Start
   again" would drop the minimum to 50. Fixed in 34beea2.
5. Spec, low: stale statements in this file. Fixed in this commit.
6. Security, low: the 99-roll minimum is lost when an error or a shell wipe (idle, background, screenshot) ends the
   restarted session. Real; not fixed, because closing it needs a new pre-Ready exit (rule 6 API) and the owner's
   approval. New item 14.
7. Security, low: the poly1305 pin ran with `--target all`, so a zeroize edge scoped to one target passed for all.
   Reproduced, and fixed in 7c46d93.
8. Security, low: the owner's intent for items 5, 6 and 12. The same outcome as finding 1.
9. Recompute, low: the same figure as finding 2, checked on its own (99 x log2 6 = 255.91). The same outcome as
   finding 2.

**Suite at 34beea2** (toolchain 1.98.1, cargo-llvm-cov 0.9.1; git status clean before and after; the logs stay in the
session scratchpad):

```text
cargo fmt --all --check                                         exit 0
cargo clippy --workspace --all-targets --locked -- -D warnings  exit 0
cargo clippy ... --all-features --locked -- -D warnings         exit 0
cargo test --workspace --locked                                 exit 0  core lib 161 passed, 1 ignored; ceremony 5,
                                                                        kat 7, kcr_release 3, os_source 2,
                                                                        typestate 1, vectors 4
cargo test -p keepcrypt-core --locked --features test-sources   exit 0  lib 189 passed, 1 ignored; ceremony 5,
                                                                        check_flow 6, error_injection 11, kat 7,
                                                                        kcr 3, no_panic 9, no_secret_text 5,
                                                                        os_source 2, panic_wipe 4,
                                                                        source_substitution 5, typestate 1, vectors 4
cargo llvm-cov ... --fail-under-lines 95 --summary-only         exit 0  lines 8272, missed 216, 97.39%;
                                                                        regions 96.87%; functions 96.27%
cargo deny --locked check                                       exit 0  advisories, bans, licenses, sources ok
cargo audit                                                     exit 0  94 crate dependencies, no vulnerabilities
cargo vet --locked                                              exit 0  Vetting Succeeded (14 fully audited,
                                                                        76 exempted)
sh scripts/check-path-deps.sh                                   exit 0  clean, 90 packages outside the workspace
python3 tools/verify/verify.py --selftest          (3.12.5)     exit 0  selftest passed: 11 checks
/usr/bin/python3 tools/verify/verify.py --selftest (3.9.6)      exit 0  selftest passed: 11 checks
sh scripts/banned-api-check.sh            (sh, dash)            exit 0  clean, 161 files scanned
sh scripts/banned-api-check.sh --selftest                       exit 0  selftest: 251 passed, 0 failed
sh scripts/canaries.sh                    (sh, dash)            exit 0  PASS: all 54 checks ran
python3 scripts/age-interop.py --core     (Homebrew age 1.3.2)  exit 0  all 11 accepted files decrypt; 14 of the
                                                                        17 armor cases refused (3 notes); both
                                                                        directions ok
--artifact aarch64-apple-darwin, aarch64-apple-ios, -ios-sim    exit 0  clean; _getentropy, _CCRandomGenerateBytes
                                                                        imported
```

The Pi and Android release builds cannot run on this Mac: secp256k1-sys's build script finds no
`arm-linux-gnueabihf-gcc` and no NDK clang (exit 101), so those four scans are CI's. Re-run for this record at
34beea2: the unit tests behind the items ticked here (`seed::`, `descriptor::`, `ur::`, `seal::tests`,
`seal::crockford`, `backup::`, `kat::tests`, `session::tests::stub`) give 101 passed, 1 ignored, and tests/vectors.rs
4 passed.

**Proof for the items ticked here** (every test named passes in the runs above):
- Group 0, branch protection: the ruleset above.
- Group 4, `seed.rs`: `seed::tests::*` (12: bip39_vectors_json, commitment_cases, mixed_cases_and_their_words,
  dice_only_matches_coldcard, bip84_fingerprint_and_first_address, the_length_of_r_is_hashed,
  every_bit_of_d_reaches_c_and_e, every_bit_of_e_reaches_the_words, s_from_the_words_equals_s_from_e,
  secret_xpriv_derives_in_place_and_erases, empty_passphrase_seed_zeroizes, tags_match_keepcrypt_json); the residuals
  accepted (item 6); the 16 of 24 approved (item 9).
- Group 5, braille vectors: check 8 on both Pythons and the one-time SeedBook PDF check; `fd75c236...` approved
  (item 3).
- Group 5, KAT group Braille: `kat::tests::a_damaged_braille_table_fails_the_group`,
  `braille_constants_match_braille_json`, `two_swapped_words_fail_the_wordlist_group` and
  `every_group_passes_and_fails_under_its_fault`.
- Group 6, `crypto-account` and the export: `descriptor::tests::*` (8, among them
  bcr_2020_015_shield_and_the_full_example, zero_fingerprints_are_omitted, bip39_passphrases,
  every_wallet_matches_watchonly_json and the_export_zeroizes_every_field) and
  `ur::tests::ur_vectors_write_and_read_back`; the residuals accepted.
- Group 7, `seal/crockford.rs` and derivation: `seal::crockford::tests::*` (3) and `seal::tests::*` (9, among them
  every_seal_json_field, the_dashed_code_gives_a_different_tag, the_recheck_url_of_vector_1 and seal_code_zeroizes);
  the hmac residual accepted.
- Group 8, vectors: check 11 on both Pythons (11 accepted and 44 refused files); age_cli_written.json approved as
  written with 1.3.2 (item 7).
- Group 8, `backup/age.rs`: `backup::age::tests::*` (9, among them every_cctv_scrypt_file_reaches_its_outcome,
  the_writer_rebuilds_every_written_file, every_refused_file_gives_its_error, no_flipped_bit_is_accepted and
  a_round_trip_at_work_factor_18); the residuals accepted, and Poly1305's r and s wiped (b4871b9).
- Group 8, Backup API: `backup::tests::round_trips_at_work_factor_18`,
  `two_backups_of_one_session_differ_and_both_verify`, `other_passphrases_do_not_verify`,
  `another_seed_under_this_passphrase_is_a_mismatch`, `nothing_before_a_passphrase`,
  `stub::encrypt_reads_key_salt_nonce_and_name_in_order` and `the_age_cli_files_decrypt` (the 1.3.2 files, item 7).
- Group 8, "Check a backup": `backup::tests::decrypt_backup_reads_backup_json`, `checked_backup_zeroizes`,
  `stub::decrypt_backup_runs_the_age_group`, tests/vectors.rs
  (`backup_json_and_the_age_cli_files_through_decrypt_backup`, `seal_json_vector_1_through_a_checked_backup`) and
  tests/ceremony.rs.
- Group 10, tests/vectors.rs: its 4 tests and the unit tests its "As built" note names; approved as built (item 9).
- Verification, "All vectors pass": verify.py's 11 checks on both Pythons, the CCTV files through
  `backup::age::tests::every_cctv_scrypt_file_reaches_its_outcome`, BIP39 through `seed::tests::bip39_vectors_json`
  and the Bip39 KAT, and the tests above.

**The push.** The 12 commits were pushed to origin/m1-core at 34beea2 (PR #4). CI on 34beea2, the first run with
the armor fix: https://github.com/bitwilll/keepcrypt/actions/runs/38041799043 (pull_request, 09:33-09:38 UTC),
conclusion success, all 14 check runs passed. From its logs:

```text
age-interop (age 1.1.1)  age package 1.1.1-1ubuntu0.24.04.3; age --version: 1.1.1
                         ok: age -> KeepCrypt and KeepCrypt -> age at work factor 18, armored and binary; wrong
                           passphrases refused by both; age_cli_written.json decrypted by both
                         ok: age decrypted all 11 backup.json age files the readers accept, and also refused 17 of
                           the 17 armor cases they refuse
                         ok: core read age's files (decrypt_backup), age read core's fresh work-factor-18 backups,
                           and age refused a wrong passphrase
cross (arm-unknown-linux-gnueabihf)  clean, 2 file(s): no marker, no test key, no other RNG symbol; getrandom imported
cross (aarch64-linux-android)        clean, 2 file(s): ... getrandom imported
cross (armv7-linux-androideabi)      clean, 2 file(s): ... getrandom imported
cross (x86_64-linux-android)         clean, 2 file(s): ... getrandom imported
cross (aarch64-apple-ios)            clean, 2 file(s): ... _CCRandomGenerateBytes imported
cross (aarch64-apple-ios-sim)        clean, 2 file(s): ... _CCRandomGenerateBytes imported
coverage      189 passed, 1 ignored; TOTAL regions 96.87%, functions 96.27%, lines 8272, missed 216, 97.39%
test          lib 161 passed, 1 ignored (default); 189 passed, 1 ignored (test-sources)
gates         verify.py: selftest passed: 11 checks; banned-api selftest: 251 passed, 0 failed; PASS: all 54 checks ran
verifier      /usr/bin/python3 3.9: selftest passed: 11 checks
supply-chain  Vetting Succeeded (14 fully audited, 76 exempted)
```

In CI, age 1.1.1 refuses all 17 armor cases the readers refuse, where 1.3.2 accepts three of them. db5b884 and
its follow-ups change only this file and two comments in core/src/backup/armor.rs (9f0e66c: age began skipping
leading whitespace in 1.3.0, not 1.2, as d8b5d25's message says); their push runs CI again.

**Ticked after review (2026-10-10).** The lead re-read run 38041799043 (all 14 Entropy check runs pass; the
age-interop, six scan and coverage lines above checked against the job logs) and ticked the items that waited on
it: group 11 `release_probe.rs` (the six scans), group 12's CI jobs and coverage, group 13 Review, and Verification
"Backup" (age-interop against Ubuntu's 1.1.1), "The release artifact scan is clean on all six targets" and
"Clean ... CI is green on `m1-core`". None of the 12 owner items waits on the owner any more; new items 13 and 14
do, but they are low and do not block the gate.

### M1 gate status: MET, approved by the owner and merged (PR #4, 2026-10-10)
The gate in docs/build-plan.md asks for all vectors passing, the source-substitution and error-injection tests
passing, and at least 95% line coverage in `core/`. All three hold locally and in CI on 34beea2 (coverage 97.39%;
run 38041799043, all 14 Entropy check runs green, including age-interop against Ubuntu's age 1.1.1 and the six
release-artifact scans). Every one of the 12 owner items is answered and applied (2026-10-10), every M1 plan and
Verification item is ticked with its proof, and ruleset 24833307 requires the 14 Entropy check runs on `main`. The
commits after 34beea2 change only this file and two comments; CI runs on them after the push. New owner items 13
and 14 are low and do not block the gate. Per CLAUDE.md, M2 does not start until the owner approves.

**Approved and merged (2026-10-10).** The owner approved the gate ("approve M1"). CI on 56337a9, the final head,
passed all 14 required Entropy check runs (the Vercel check, not required, failed as it does on every PR). PR #4 was
marked ready and merged with a merge commit, a87a6ee ("Merge Entropy M1: core crate (keepcrypt-core) (#4)"), and
`m1-core` was deleted. The owner then asked for the M2 plan ("yes, start planning M2"); M2 work happens on
`m2-verifier`.

### M2: local proof (2026-10-11, at 5100b6f)
Apple M4 Max, macOS 27.0.1, toolchain 1.98.1 (rust-toolchain.toml), python3 3.12.5 and `/usr/bin/python3` 3.9.6, run
from `Entropy/`; the shell scripts also under `dash`. M2 ran 2026-10-10 to 2026-10-11 on `m2-verifier` (draft PR #5)
in four stages. Each stage made its planned commits, had them reviewed three ways (plan, security, recompute), fixed
what the reviews found, ran the full suite, and was pushed so that CI ran on its head. Plan items are ticked above
only where the proof covers them. Every M2 item is now ticked (the end of this section).

**Group 0 baseline** (2026-10-10, before commit 2; for group 8's budget). It was taken at a7c941e, which differs from
90b6ab9 only in this file (`git diff --stat 90b6ab9 a7c941e`: 812 insertions, 1 deletion), so code, scripts,
vectors and docs are 90b6ab9's. Commands ran one at a time, timed with zsh `time`:

```text
python3 tools/verify/verify.py --selftest           (3.12.5)  11/11 "selftest passed: 11 checks"  5.565 s (5.40 user)
python3 -I tools/verify/verify.py --selftest        (3.12.5)  11/11                               5.392 s (5.22 user)
/usr/bin/python3 tools/verify/verify.py --selftest  (3.9.6)   11/11                               9.174 s (9.01 user)
                                                              the 11 "ok" lines identical on 3.12 and 3.9
sh scripts/canaries.sh                                        exit 0, "PASS: all 54 checks ran"   1:09.36 (80.33 user)
cargo test --workspace --locked (warm target/)                183 passed, 0 failed, 1 ignored     20.365 s
    core lib 161 (+1 ignored), ceremony 5, kat 7, kcr_release 3, os_source 2, typestate 1, vectors 4; ffi, pi,
    pi-sim 0; doc-tests 0
cargo test -p keepcrypt-core --locked --features test-sources 251 passed, 0 failed, 1 ignored     1:03.11
    core lib 189 (+1 ignored), ceremony 5, check_flow 6, error_injection 11, kat 7, kcr 3, kcr_release 0,
    no_panic 9, no_secret_text 5, os_source 2, panic_wipe 4, source_substitution 5, typestate 1, vectors 4
```

**Commits a7c941e..5100b6f.** 44 commits, oldest first, by stage. Each gives its hash, its subject, and one line of
proof from the stage's reports.

Stage A: planned commits 2-5, then the stage-A review fixes (pushed head 86c4c0d).
- 5d222f5 docs: the owner-approved M2 edits (Q19): D is shown like C, a run records C first, verify/ holds two files.
  Proof: only Entropy/docs/ (4 files); `verify.py --selftest` 11/11 with `-I` on both Pythons; canaries 54/54.
- 99edb77 verify, scripts, ci, CLAUDE.md: split into the shipped verify.py and tools/verify/vectorgen.py as a pure
  move. Proof: the seven writers leave `vectors/` byte-identical on both Pythons; `--selftest` 11/11 with the
  baseline's lines; age-interop in both modes; canaries 54/54.
- 76dd1fb verify, vectors, core: provenance names vectorgen.py: the seven descriptions, SOURCES.md, the
  age_cli_written.json note and six core comments. Proof: each file equals its old bytes with `description`
  blanked; the core diff is `//` lines only; `cargo test` 183 and 251; 11/11 on both Pythons.
- 22883dc scripts: Python networking and clipboard patterns in the banned-API gate, with selftest fixtures (Q23).
  Proof: gate `--selftest` 297/297 (251 before) under sh and dash; the gate before it finds none of the 27 new hits.
- bbbb599 scripts/age-interop.py: --generate names vectorgen.py check 11 in age_cli_written.json's description.
  Proof: the whole-repo grep then finds only age_cli_written.json:2 and SOURCES.md's record of it; age-interop passes.
- 2425cdb verify: the snapshot section's comment names M9's re-check (Q22), not an M2 one. Proof: a comment only.
- 0610f3e vectors/SOURCES.md: say that records of pre-split work name code by the file that holds it now.
  Proof: one paragraph; `--selftest` 11/11 (check 3) on both Pythons.
- 64c4fc7 scripts: the banned-API gate catches a Python import continued after "from \". Proof: 4 new fixtures,
  one hit each, none hit by the gate before it; dropping a new pattern or its anchor turns the selftest red.
- 5cc295d scripts: the gate's Python network list takes _socket and _ssl, and its residuals name importlib.
  Proof: 2 new fixtures, one hit each; removing either name fails exactly its fixture.
- 42d8552 scripts: gate fixtures pin the Python patterns' boundaries and the .py-only dispatch. Proof: gate code
  unchanged; `--selftest` 309/309 under sh and dash; every listed boundary mutant fails on its own line.
- 86c4c0d tasks/todo.md: review corrections to the M2 plan text and the proof of groups 1 and 2. Proof: the 30
  provenance verdicts pasted; the clean-checkout count is 160 files; the mutant count is 11 lines, not 14.

Stage B: planned commits 5b, 6 and 7, then the stage-B review fixes (pushed head 9301be3). The stage was a resumed
run: its fixer found 5cc4d24, e37f8a5 and bb989cb already made, and checked each against its finding.
- df1c053 scripts: complete the banned-API gate's Python clipboard and network lists (stage-A review, Q23).
  Proof: `--selftest` 342/342 (309 before) under sh and dash; the gate before it finds none of the 22 new hits; 38
  mutants each fail on their own line.
- 0978754 verify: startup guards, the known answers and verify.py selftest; vectorgen check 12 (verify.py ships
  alone). Proof: `verify.py selftest` 5 groups on both Pythons; `--selftest` 12/12 (5.8 s and 10.2 s); a mutant copy
  for each rule fails check 12; canaries 54/54.
- 3727711 verify: input parsers, verification_run, render, insert_line and the registry URL builders; urls and insert
  known answers, INPUT_CASES and the keepcrypt.json tie in check 12. Proof: 7 groups on both; 12/12 (5.9 s and
  10.3 s); 17 input cases and the tie (3 mixed, 6 dice-only cases) pass; the URLs equal core's pinned literals.
- 5cc4d24 tools/verify/vectorgen.py: KNOWN_ANSWER_BIP39_ENTRIES' comment says which english entries 12 and 14 are.
  Proof: a comment only (finding 2).
- e37f8a5 tools/verify/vectorgen.py: --verify-py's usage and --help say it replaces the subject of check 12's rules
  (a)-(e) only. Proof: text only (finding 1).
- bb989cb tools/verify/vectorgen.py: an input case pins parse_hex32's "non-ASCII first" rule. Proof: the 18th case;
  a copy without the non-ASCII pass gives (D, 3) and fails on both Pythons (finding 8).
- 2db1b6f verify: check 12 changes every known answer in turn, and refuses any read of KNOWN_ANSWERS but
  known_answers(KNOWN_ANSWERS). Proof: the sweep changes all 214 values; 14 verify.py mutants that passed at bb989cb
  fail on both (finding 4).
- e850278 tools/verify/vectorgen.py: check 12 holds its own rules to controls that must fire. Proof: 14 vectorgen
  mutants fail on both (finding 6).
- 5ed7ab9 tools/verify/vectorgen.py: check 12's audit refuses changes to a file by path. Proof: a copy that
  truncated a file passed at bb989cb and fails now; 15 drop-one mutants fail (finding 10).
- 7679ee2 scripts: gate fixtures pin each "any letter case" clipboard pattern in both cases. Proof: `--selftest`
  346/346 under sh and dash; 62 letter-case mutants fail (finding 5).
- 9301be3 tools/verify/vectorgen.py: check 12 runs the lone copy as Python 3.8; tasks/todo.md unticks two items short
  of their proof. Proof: the 3.8.18 run exits 2 with the version line alone; 4 guard mutants fail (finding 9).

Stage C: planned commits 8 and 9, then the stage-C review fixes (pushed head 0d2ff75).
- fcb3481 verify, vectors: --write-agreement-vectors, vectors/agreement.json and check 13 (coverage counts, Coldcard
  subset); SOURCES.md and UNLISTED. Proof: 1,000 ceremonies and 28 refusals, 4,155,350 bytes, the same bytes on both
  Pythons (1.10 s and 1.79 s); check 13 3.0 s and 5.1 s; 13/13; of 20 scratch mutants, 18 fail before and after a
  re-baseline, and 2 (no drawn extras, no case 6) fail only before one, since either alone still gives every source
  and an empty extra; canaries 54/54.
- 1f86f2c tests: core/tests/agreement.rs replays agreement.json under test-sources, with its [[test]] entry.
  Proof: 9 passed in 1.17 s (8.47 s on one thread); 92 planted changes each fail their case and field; a core with
  another `REGISTRY_ORIGIN` fails every combination at `recheck_url`; the default run skips it.
- 7b3d199 tasks/todo.md: group 8's agreement-core canary changes a value in expect, not a roll. Proof: on a scratch
  copy the seal-tag change fails `24-mixed-pi-083: seal_tag_hex`; the roll change failed at `push_roll: InvalidRoll`
  (finding 1).
- 9a3902a verify, vectors: agreement.json's provenance names each expected value's source. Proof:
  `--write-agreement-vectors` changes only the spec's `expect` line (now 4,155,498 bytes); 13/13; agreement 9/9
  (finding 2).
- a3a4d4e tools/verify/vectorgen.py: check 13 holds the dice quota apart from verify.py's DICE. Proof: copies with
  `max_rolls` 257, `min_rolls_12_words` 49 or `min_rolls_24_words` 98, re-baselined, passed before and fail now on
  both Pythons (finding 3).
- 9fc299f tools/verify/vectorgen.py: check 13 pins each refusal to its planned boundary. Proof: the boundary mutants
  (two passed all 13 checks and core's test before) and a 97-roll restart fail on both (finding 4).
- 0d2ff75 tools/verify/vectorgen.py: check 13 holds its own rules to controls that must fire. Proof: each rule
  returning `[]`, or removed with its verify.py fault, fails on both; `cargo test` 260 and 183 (finding 5).

Stage D: planned commits 10-13, then the stage-D review fixes (pushed head 5100b6f).
- 11d1163 verify: the mixed and dice commands, the run known answers, the pipe notice, the quiet argument parser and
  the docstring guide; check 12 runs the commands piped, in a pty and under a Latin-1 locale. Proof: 8 groups on
  both; 13/13 (12.2 s and 22.9 s); check 12 passes nine repeat runs; 32 scratch mutants fail on both; canaries 54/54.
- a45c2d0 tools/verify/vectorgen.py: check 13 pins the planned case mix, case by case. Proof: three thinner mixes
  passed before and fail now on both; agreement.json regenerates unchanged; canaries 54/54 in 117 s.
- 6dcce94 scripts: the agreement.json tamper canary, agreement-core, verifier-import, verifier-echo,
  verifier-echo-upper, verifier-tty and verifier-reach; the pinned count goes from 54 to 61. Proof: canaries 61/61
  (160 s under sh, 150 s under dash); a disarmed agreement-core reports FAIL.
- c9b5a5d ci: the gates and verifier (python 3.9) job comments name 13 checks and the M2 canaries. Proof: comments
  only; the workflow parses to the same YAML (`ruby -ryaml`).
- 1b719ff CLAUDE.md: Commands for M2. Proof: each changed command run as written (group 8's item).
- 12ce409 tools/verify/vectorgen.py: check 12 holds every piped run to the leak rule. Proof: two copies that leaked
  in a fault-twin run and in the locale run passed at 1b719ff and fail now on both (F1).
- a5543a6 tools/verify/vectorgen.py: check 12 cuts each run's rolls so every typed line meets the leak rule.
  Proof: a copy that echoes every roll line after the first fails on both (F6).
- ae5c3c5 tools/verify/vectorgen.py: check 12 pins each command run's stderr and transcript whole. Proof: a copy
  writing `repr(report)` to stderr, and an echo of the dice run's `456`, fail on both (F7, F6, F15 part 2).
- 22908f7 tools/verify/vectorgen.py: check 12 types C and the rolls as a user may type them. Proof: the three
  typed-form copies fail on both (F15 parts 1, 3 and 4).
- 6b1d8b5 tools/verify/vectorgen.py: check 12 refuses arguments at each parser, --words missing or 18, and an @file.
  Proof: copies with plain subparsers, `fromfile_prefix_chars`, `default=12` or an 18 fail on both (F8, F10, F11).
- 7134a09 tools/verify/vectorgen.py: check 12 takes the exit-70 path in an audited run, its line pinned.
  Proof: a handler printing the exception's text, or writing a crash log, fails on both (F8, F13).
- 8ced14f tools/verify/vectorgen.py: check 12's rule (a) bans the name type. Proof: a copy that writes a file through
  `type(sys.stderr.buffer.raw)` fails rule (a) on both (F8).
- b41cdc6 tools/verify/vectorgen.py: check 12's locale and in-process runs are held to controls that must fire.
  Proof: vectorgen copies without either part, or with either check off, fail on both (F12).
- 8a1b0c6 verify: the guide no longer says that type-ahead is never shown. Proof: wording only; canaries 61/61
  under sh (2:33) and dash (2:34) (F9, F14).
- 5100b6f tasks/todo.md: the plan text matches the code; check 12's item ticked on commit 11's canaries.
  Proof: plan text only (F2-F5).

**Review findings.** 46 in all: 1 high, 9 medium, 36 low. 43 were fixed in the stages' fix commits, two of them in
part: stage C's boundary finding, whose case-mix part a45c2d0 made, and F15. 3 were closed by later planned commits,
one of them (stage B's run, render and range finding) but for `check_url`'s nonce-length guard. Two parts stay open,
both low: F15 part 5 and that guard (open items, below).
- Stage A, 16 (0 high, 1 medium, 15 low):
  - medium (plan): `scripts/age-interop.py:272`, the `--generate` template, still wrote "verify.py --selftest ...
    (check 11)", so a regeneration would put false provenance back. Fixed in bbbb599; 86c4c0d widened the plan's
    grep to the whole repo;
  - low: 14 fixed in bbbb599, 2425cdb, 0610f3e, 64c4fc7, 5cc295d, 42d8552 and 86c4c0d. F10 (clipboard routes
    outside the planned list) was left for a decision. Commit 5b (df1c053) added the routes it named, beyond the
    lists the owner approved in Q23 (an open item for the owner, below), but for a bare `clip`, which the gate lets
    pass by design (banned-api-check.sh:371).
- Stage B, 10 (0 high, 1 medium, 9 low):
  - medium (recompute): check 12 ran one value per known-answer group, never the "unreadable" branch, and a copy
    could change the table at run time. Fixed in 2db1b6f (a sweep of all 214 values; `known_answers(table)`);
  - low: 7 fixed in 5cc4d24, e37f8a5, bb989cb, e850278, 5ed7ab9, 7679ee2 and 9301be3. 2 were left to planned commits
    and closed there: the URL origin, shared by vectorgen and verify.py (core's agreement test compares the URLs
    whole, 1f86f2c), and the run, render and range gaps (check 13, fcb3481; the command runs, 11d1163), closed but
    for one part: no test pins `check_url`'s nonce-length guard, so the finding's "nonce length check removed"
    mutant is still not caught (checks 12 and 13 give it only 8-byte nonces; open item, below).
- Stage C, 5 (0 high, 2 medium, 3 low):
  - medium (plan): the planned agreement-core canary changed a roll, which core refuses before it compares any
    value. Fixed in 7b3d199 (plan) and built that way in 6dcce94;
  - medium (recompute): check 13 never pinned the 24 boundary refusals to their boundary, so an off-by-one in
    verify.py's range passed after a re-baseline. Fixed in 9fc299f; its case-mix part in a45c2d0;
  - low: fixed in 9a3902a (provenance wording), a3a4d4e (the quota apart from DICE) and 0d2ff75 (controls).
- Stage D, 15 (1 high, 5 medium, 9 low):
  - high (security, F6): rule (f) missed a terminal echo of every roll line after the first, since the last line of
    a 50-roll run was shorter than the leak rule's 12. Fixed in a5543a6 and ae5c3c5;
  - medium (plan, F1): the leak rule skipped the 16 fault-twin runs and the locale run's stderr. Fixed in 12ce409;
  - medium (security, F7): the leak rule saw D only as hex, and stderr and the transcript were checked only for what
    they must hold. Fixed in ae5c3c5;
  - medium (security, F8): `ArgumentParser`'s keywords were not limited (an `@file` would be read), the exit-70 path
    ran only in process, and the name `type` was open. Fixed in 6b1d8b5, 7134a09 and 8ced14f;
  - medium (recompute, F10): a refused `--words` value at the subcommand's parser was never tested. Fixed in 6b1d8b5;
  - medium (recompute, F11): nothing pinned that `--words` has no default and takes only 12 and 24. Fixed in 6b1d8b5;
  - low: F2-F5 fixed in 5100b6f, F9 and F14 in 8a1b0c6, F12 in b41cdc6, F13 in 7134a09, and F15 parts 1-4 in 22908f7
    and ae5c3c5. F15 part 5 is open (deviations, below).

**Suite at 5100b6f** (stage D's run, 2026-10-11; git status clean before and after; logs in the session scratchpad):

```text
cargo fmt --all --check                                         exit 0
cargo clippy --workspace --all-targets --locked -- -D warnings  exit 0
cargo clippy ... --all-features --locked -- -D warnings         exit 0
cargo test --workspace --locked                                 exit 0  core lib 161 passed, 1 ignored; ceremony 5,
                                                                        kat 7, kcr_release 3, os_source 2,
                                                                        typestate 1, vectors 4 (17.9 s)
cargo test -p keepcrypt-core --locked --features test-sources   exit 0  lib 189 passed, 1 ignored; agreement 9
                                                                        (1.15 s); ceremony 5, check_flow 6,
                                                                        error_injection 11, kat 7, kcr 3, no_panic 9,
                                                                        no_secret_text 5, os_source 2, panic_wipe 4,
                                                                        source_substitution 5, typestate 1,
                                                                        vectors 4 (60.0 s)
cargo llvm-cov ... --fail-under-lines 95 --summary-only         exit 0  lines 8272, missed 216, 97.39%;
                                                                        regions 96.87%; functions 96.27%
cargo deny --locked check                                       exit 0  advisories, bans, licenses, sources ok
cargo audit                                                     exit 0  94 crate dependencies, no vulnerabilities
cargo vet --locked                                              exit 0  Vetting Succeeded (14 fully audited,
                                                                        76 exempted)
sh scripts/check-path-deps.sh                                   exit 0  clean, 90 packages outside the workspace
python3 -I tools/verify/vectorgen.py --selftest   (3.12.5)      exit 0  selftest passed: 13 checks (12.5 s)
/usr/bin/python3 -I ... vectorgen.py --selftest   (3.9.6)       exit 0  selftest passed: 13 checks (23.5 s)
python3 -I tools/verify/verify.py selftest        (3.12.5)      exit 0  8 known-answer groups (0.03 s)
/usr/bin/python3 -I ... verify.py selftest        (3.9.6)       exit 0  8 known-answer groups (0.09 s)
sh scripts/banned-api-check.sh            (sh, dash)            exit 0  clean, 165 files scanned
sh scripts/banned-api-check.sh --selftest (sh, dash)            exit 0  selftest: 346 passed, 0 failed
sh scripts/canaries.sh                    (sh, dash)            exit 0  PASS: all 61 checks ran (155.2 s, 154.9 s)
python3 scripts/age-interop.py --core     (Homebrew age 1.3.2)  exit 0  three ok lines; 3 notes (armor cases that
                                                                        age 1.3.2 accepts and the readers refuse)
--artifact aarch64-apple-darwin, aarch64-apple-ios, -ios-sim    exit 0  clean; _getentropy, _CCRandomGenerateBytes
                                                                        imported (also from fresh target dirs)
```

Not run there: the eight writers, which write files (commit 13 ran them at 1b719ff and `vectors/` stayed
byte-identical; after 1b719ff only check 12, the verify.py guide and this file change, and check 13 regenerates
agreement.json byte for byte at 5100b6f); `TRYBUILD=overwrite`, which is only for a toolchain or trybuild bump; and
the Pi and Android scans, which need a cross toolchain this Mac lacks (CI's `cross` job).

Re-run for this record at 5100b6f (2026-10-11):

```text
python3 -I tools/verify/verify.py selftest; /usr/bin/python3 -I ... selftest   exit 0 on both; stdout byte-identical
cargo test -p keepcrypt-core --locked --features test-sources --test agreement
                                                   9 passed; 0 failed (1.15 s; 9.19 s user on 16 threads)
check 12's runs, counted by a scratch script that wraps audited_run, terminal_run and inprocess_command_problems
(both Pythons)                                     no problem; 54 audited runs in the command part (53 piped and the
                                                   locale control), 5 terminal runs, 3 in-process calls (the run and
                                                   its 2 controls); 69 audited runs in all
python3 -I tools/verify/vectorgen.py --selftest (3.12.5)             exit 0  selftest passed: 13 checks (12.2 s)
/usr/bin/python3 -I tools/verify/vectorgen.py --selftest (3.9.6)     exit 0  selftest passed: 13 checks (23.0 s)
  (the tree at 5100b6f with this file's edit, which no check reads)
```

**`verify.py selftest`** (3.12.5 and 3.9.6; stdout byte-identical, stderr empty, exit 0):

```text
ok   hash
ok   bip39
ok   seed
ok   seal
ok   braille
ok   urls
ok   insert
ok   run
selftest passed: 8 known-answer groups
```

**Run transcripts** (2026-10-11, at 5100b6f, 3.12.5; on 3.9.6 both streams are byte-identical, exit 0). These are
public test vectors from vectors/agreement.json, marked "never fund" (rule 12). The inputs come from the file
through a short Python line, not typed literals. A user types them at the prompts instead, since a pipe leaves
them in shell history (the guide). `$S` is a scratch directory outside the repo.

```text
$ INPUTS='import json,sys;c=[x for x in json.load(open("vectors/agreement.json"))["ceremonies"] if x["name"]==sys.argv[1]][0];g=lambda h:" ".join(h[i:i+4] for i in range(0,64,4));e=c["expect"];c["mode"]=="mixed" and print(g(e["c_hex"]),g(e["d_hex"]),sep="\n");print(c["rolls"]+"\n")'
$ python3 -I -c "$INPUTS" 12-mixed-pi-000          # what the pipe carries: C, D, the rolls, an empty line
21d4 24c3 d4ab 0130 3fe0 1593 ea19 00d4 cb4d d1f1 3d92 6cdc 7baf 0c1b c73e 9203
4a38 fcf5 fc3a 6cb5 cadb c26c a1d6 2efa 9bc9 7c20 6f6c 9211 e5b4 0939 92bb 918e
56143225411155643344655336451655425545354524411345

$ python3 -I -c "$INPUTS" 12-mixed-pi-000 | python3 -I tools/verify/verify.py mixed --words 12 >"$S/out" 2>"$S/err"; echo "exit $?"
exit 0
--- stderr (each prompt line ends in one space, dropped here)
input read from a pipe or file: clear it from your shell history and delete any file
C, as written down before the first roll:
C read: 21d4 24c3 d4ab 0130 3fe0 1593 ea19 00d4 cb4d d1f1 3d92 6cdc 7baf 0c1b c73e 9203
D, from the device's "Reveal D" screen:
D read: 64 hex digits
rolls (an empty line ends them):
50 rolls, 50 in all
rolls (an empty line ends them):
--- stdout
VERIFICATION RUN: a disposable test seed. Never fund it; erase this run and clear the terminal afterwards.
commitment: C matches D
rolls: 50 (129.2 bits)
entropy: afb7b84a188ca710c97309314c7d3464
seal-id: X406RHQ0 ⠭⠼⠙⠚⠋⠗⠓⠟⠼⠚
seal-tag: e9006c46e0a02487611658d1e7d76c41bfe943861d4b0dfb7f3bcedfdb426539
lookup-prefix: e9006
seal-colour: 1 #E69F00
seal-grid: ........
seal-grid: ........
seal-grid: .##..##.
seal-grid: ##....##
seal-grid: .#....#.
seal-grid: .##..##.
seal-grid: ###..###
seal-grid: ........
recheck-url: https://registry.invalid/check#t=e9006c46e0a02487611658d1e7d76c41bfe943861d4b0dfb7f3bcedfdb426539
insert: 01 device 1/1 seq 01 seedbook 1406 quick | ⠟q ⠥u ⠊i/e ⠉c ⠅k~ | ⠟⠥⠊⠉⠅
insert: 02 device 1/1 seq 02 seedbook 1519 saddle | ⠎s ⠁a ⠙d/f ⠙d/f ⠇l~ | ⠎⠁⠙⠙⠇⠑
insert: 03 device 1/1 seq 03 seedbook 0149 barely | ⠃b ⠁a ⠗r/w ⠑e/i ⠇l~ | ⠃⠁⠗⠑⠇⠽
insert: 04 device 1/1 seq 04 seedbook 0393 country | ⠉c ⠕o ⠥u ⠝n ⠞t~ | ⠉⠕⠥⠝⠞⠗⠽
insert: 05 device 1/1 seq 05 seedbook 1620 skill | ⠎s ⠅k ⠊i/e ⠇l ⠇l~ | ⠎⠅⠊⠇⠇
insert: 06 device 1/1 seq 06 seedbook 1092 mask | ⠍m ⠁a ⠎s ⠅k -- | ⠍⠁⠎⠅
insert: 07 device 1/1 seq 07 seedbook 0303 chair | ⠉c ⠓h/j ⠁a ⠊i/e ⠗r/w~ | ⠉⠓⠁⠊⠗
insert: 08 device 1/1 seq 08 seedbook 0778 gentle | ⠛g ⠑e/i ⠝n ⠞t ⠇l~ | ⠛⠑⠝⠞⠇⠑
insert: 09 device 1/1 seq 09 seedbook 0395 course | ⠉c ⠕o ⠥u ⠗r/w ⠎s~ | ⠉⠕⠥⠗⠎⠑
insert: 10 device 1/1 seq 10 seedbook 0800 glue | ⠛g ⠇l ⠥u ⠑e/i -- | ⠛⠇⠥⠑
insert: 11 device 1/1 seq 11 seedbook 0617 escape | ⠑e/i ⠎s ⠉c ⠁a ⠏p~ | ⠑⠎⠉⠁⠏⠑
insert: 12 device 1/1 seq 12 seedbook 1611 sing | ⠎s ⠊i/e ⠝n ⠛g -- | ⠎⠊⠝⠛
seal-code: A7EN7-R3NFS-H9E9T-9T3CH-TFVVZT
note: every line above must equal what the device showed; a difference is a typing error or a faulty device
note: for 12 words, 50-98 rolls is valid only for a first ceremony, never after "Match found", which takes 99
note: the device's check QR adds its fresh nonce to the re-check URL, so no run can show it or a go-ahead code
```

```text
$ python3 -I -c "$INPUTS" 24-dice_only-phone-000   # what the pipe carries: the rolls, an empty line
111314222414261154463151153234512655513634452115416112356111515224545426316633241615643416536323145

$ python3 -I -c "$INPUTS" 24-dice_only-phone-000 | python3 -I tools/verify/verify.py dice --words 24 >"$S/out" 2>"$S/err"; echo "exit $?"
exit 0
--- stderr (each prompt line ends in one space, dropped here)
input read from a pipe or file: clear it from your shell history and delete any file
rolls (an empty line ends them):
99 rolls, 99 in all
rolls (an empty line ends them):
--- stdout
VERIFICATION RUN: a disposable test seed. Never fund it; erase this run and clear the terminal afterwards.
rolls: 99 (255.9 bits)
entropy: 6d0991e66f04ebd5d666b016f47b33a45bd22d3649e8778bc64e9fd67bcd6409
seal-id: SBNSJKF2 ⠎⠃⠝⠎⠚⠅⠋⠼⠃
seal-tag: caeb994de2afc72922707e3cc20320ad70fc5ba92cdb83b8b13168172a3cca0c
lookup-prefix: caeb9
seal-colour: 2 #56B4E9
seal-grid: ###..###
seal-grid: #.####.#
seal-grid: #..##..#
seal-grid: #..##..#
seal-grid: .#....#.
seal-grid: ##.##.##
seal-grid: ###..###
seal-grid: ..#..#..
recheck-url: https://registry.invalid/check#t=caeb994de2afc72922707e3cc20320ad70fc5ba92cdb83b8b13168172a3cca0c
insert: 01 device 1/2 seq 01 seedbook 0873 home | ⠓h/j ⠕o ⠍m ⠑e/i -- | ⠓⠕⠍⠑
insert: 02 device 1/2 seq 02 seedbook 0613 erode | ⠑e/i ⠗r/w ⠕o ⠙d/f ⠑e/i~ | ⠑⠗⠕⠙⠑
insert: 03 device 1/2 seq 03 seedbook 0973 kangaroo | ⠅k ⠁a ⠝n ⠛g ⠁a~ | ⠅⠁⠝⠛⠁⠗⠕⠕
insert: 04 device 1/2 seq 04 seedbook 1777 task | ⠞t ⠁a ⠎s ⠅k -- | ⠞⠁⠎⠅
insert: 05 device 1/2 seq 05 seedbook 0630 exchange | ⠑e/i ⠭x ⠉c ⠓h/j ⠁a~ | ⠑⠭⠉⠓⠁⠝⠛⠑
insert: 06 device 1/2 seq 06 seedbook 1880 turtle | ⠞t ⠥u ⠗r/w ⠞t ⠇l~ | ⠞⠥⠗⠞⠇⠑
insert: 07 device 1/2 seq 07 seedbook 0717 flower | ⠋f/d ⠇l ⠕o ⠺w/r ⠑e/i~ | ⠋⠇⠕⠺⠑⠗
insert: 08 device 1/2 seq 08 seedbook 1713 stock | ⠎s ⠞t ⠕o ⠉c ⠅k~ | ⠎⠞⠕⠉⠅
insert: 09 device 1/2 seq 09 seedbook 0184 black | ⠃b ⠇l ⠁a ⠉c ⠅k~ | ⠃⠇⠁⠉⠅
insert: 10 device 1/2 seq 10 seedbook 1311 phrase | ⠏p ⠓h/j ⠗r/w ⠁a ⠎s~ | ⠏⠓⠗⠁⠎⠑
insert: 11 device 1/2 seq 11 seedbook 1640 smooth | ⠎s ⠍m ⠕o ⠕o ⠞t~ | ⠎⠍⠕⠕⠞⠓
insert: 12 device 1/2 seq 12 seedbook 0582 emerge | ⠑e/i ⠍m ⠑e/i ⠗r/w ⠛g~ | ⠑⠍⠑⠗⠛⠑
insert: 13 device 2/2 seq 01 seedbook 1514 rule | ⠗r/w ⠥u ⠇l ⠑e/i -- | ⠗⠥⠇⠑
insert: 14 device 2/2 seq 02 seedbook 0181 bird | ⠃b ⠊i/e ⠗r/w ⠙d/f -- | ⠃⠊⠗⠙
insert: 15 device 2/2 seq 03 seedbook 1738 summer | ⠎s ⠥u ⠍m ⠍m ⠑e/i~ | ⠎⠥⠍⠍⠑⠗
insert: 16 device 2/2 seq 04 seedbook 0489 dial | ⠙d/f ⠊i/e ⠁a ⠇l -- | ⠙⠊⠁⠇
insert: 17 device 2/2 seq 05 seedbook 0957 jealous | ⠚j/h ⠑e/i ⠁a ⠇l ⠕o~ | ⠚⠑⠁⠇⠕⠥⠎
insert: 18 device 2/2 seq 06 seedbook 0754 funny | ⠋f/d ⠥u ⠝n ⠝n ⠽y~ | ⠋⠥⠝⠝⠽
insert: 19 device 2/2 seq 07 seedbook 1182 neck | ⠝n ⠑e/i ⠉c ⠅k -- | ⠝⠑⠉⠅
insert: 20 device 2/2 seq 08 seedbook 0510 distance | ⠙d/f ⠊i/e ⠎s ⠞t ⠁a~ | ⠙⠊⠎⠞⠁⠝⠉⠑
insert: 21 device 2/2 seq 09 seedbook 0830 guilt | ⠛g ⠥u ⠊i/e ⠇l ⠞t~ | ⠛⠥⠊⠇⠞
insert: 22 device 2/2 seq 10 seedbook 1846 trade | ⠞t ⠗r/w ⠁a ⠙d/f ⠑e/i~ | ⠞⠗⠁⠙⠑
insert: 23 device 2/2 seq 11 seedbook 1154 mother | ⠍m ⠕o ⠞t ⠓h/j ⠑e/i~ | ⠍⠕⠞⠓⠑⠗
insert: 24 device 2/2 seq 12 seedbook 0324 chronic | ⠉c ⠓h/j ⠗r/w ⠕o ⠝n~ | ⠉⠓⠗⠕⠝⠊⠉
seal-code: MEN4C-WWCGY-4KS2Q-CFQJR-3X9QEJ
note: every line above must equal what the device showed; a difference is a typing error or a faulty device
note: for 12 words, 50-98 rolls is valid only for a first ceremony, never after "Match found", which takes 99
note: the device's check QR adds its fresh nonce to the re-check URL, so no run can show it or a go-ahead code
```

Core's values for the same cases. Core's agreement test checks that core's session, fed these cases' stubs,
events and rolls, gives exactly agreement.json's `expect`: C from `commitment()`, D from `reveal_device_leg()`,
the words from `mnemonic()`, the seed bits from the inserts' SeedBook numbers, the seal from `seal()` and
`seal_from_mnemonic`, and each insert line from core's braille accessors (`words12_mixed_pi` and
`words24_dice_only_phone` cover these two cases, and pass above). A scratch script compares the transcripts' stdout
with those `expect` values:

```text
12-mixed-pi-000 expect, which core's test compares with core's own values:
  c_hex        21d424c3d4ab01303fe01593ea1900d4cb4dd1f13d926cdc7baf0c1bc73e9203
  d_hex        4a38fcf5fc3a6cb5cadbc26ca1d62efa9bc97c206f6c9211e5b4093992bb918e
  entropy_hex  afb7b84a188ca710c97309314c7d3464
  words        quick saddle barely country skill mask chair gentle course glue escape sing
  seal_tag_hex e9006c46e0a02487611658d1e7d76c41bfe943861d4b0dfb7f3bcedfdb426539
  seal_code    A7EN7-R3NFS-H9E9T-9T3CH-TFVVZT
24-dice_only-phone-000 expect, which core's test compares with core's own values:
  c_hex        null (dice-only)
  d_hex        null (dice-only)
  entropy_hex  6d0991e66f04ebd5d666b016f47b33a45bd22d3649e8778bc64e9fd67bcd6409
  words        home erode kangaroo task exchange turtle flower stock black phrase smooth emerge
               rule bird summer dial jealous funny neck distance guilt trade mother chronic
  seal_tag_hex caeb994de2afc72922707e3cc20320ad70fc5ba92cdb83b8b13168172a3cca0c
  seal_code    MEN4C-WWCGY-4KS2Q-CFQJR-3X9QEJ
12-mixed-pi-000 fields equal to expect: True [] | words equal: True | commitment line: ['C matches D'] | c_hex/d_hex null: False
24-dice_only-phone-000 fields equal to expect: True [] | words equal: True | commitment line: None | c_hex/d_hex null: True
```

**Group 6's mutation script output** (stage C, 2026-10-11; `mutate.py`, SHA-256 `6dc82adf…`, a one-off scratch
script kept out of the repo). Each run changes one recorded value of a scratch copy of agreement.json and runs that
case's test of core/tests/agreement.rs:

```text
baseline words12_mixed_pi: exit 0, message None
ok   C: exit 101, '12-mixed-pi-000: c_hex'
ok   D: exit 101, '12-mixed-pi-000: d_hex'
ok   D, dice-only, made non-null: exit 101, '12-dice_only-pi-000: d_hex'
ok   C, dice-only, made non-null: exit 101, '12-dice_only-pi-000: c_hex'
ok   n: exit 101, '12-mixed-pi-001: nonce_hex'
ok   n through the check URL: exit 101, '12-mixed-pi-001: check_url'
ok   check URL origin: exit 101, '12-mixed-pi-001: check_url'
ok   G, the next valid value: exit 101, '12-mixed-pi-001: go_ahead'
ok   G on the skip path: exit 101, '12-mixed-pi-000: go_ahead'
ok   wrong G made equal to G: exit 101, '12-mixed-pi-009: wrong_go_ahead'
ok   wrong G malformed: exit 101, '12-mixed-pi-009: wrong_go_ahead'
ok   T: exit 101, '12-mixed-pi-000: seal_tag_hex'
ok   Seal ID: exit 101, '12-mixed-pi-000: seal_id'
ok   Seal ID braille: exit 101, '12-mixed-pi-000: seal_id_braille'
ok   lookup prefix: exit 101, '12-mixed-pi-000: lookup_prefix'
ok   bucket: exit 101, '12-mixed-pi-000: bucket'
ok   grid: exit 101, '12-mixed-pi-000: grid'
ok   colour index: exit 101, '12-mixed-pi-000: colour_index'
ok   colour hex: exit 101, '12-mixed-pi-000: colour_hex'
ok   re-check URL: exit 101, '12-mixed-pi-000: recheck_url'
ok   re-check URL origin: exit 101, '12-mixed-pi-000: recheck_url'
ok   register URL: exit 101, '12-mixed-pi-000: register_url'
ok   register URL origin: exit 101, '12-mixed-pi-000: register_url'
ok   grouped code: exit 101, '12-mixed-pi-000: seal_code'
ok   grouped code without dashes: exit 101, '12-mixed-pi-000: seal_code'
ok   collision report code: exit 101, '12-mixed-pi-005: collision'
ok   collision report URL: exit 101, '12-mixed-pi-005: collision'
ok   collision report origin: exit 101, '12-mixed-pi-005: collision'
ok   collision report on a first ceremony: exit 101, '12-mixed-pi-000: collision'
ok   no first ceremony on a restart: exit 101, '12-mixed-pi-005: collision'
ok   word 1: exit 101, '12-mixed-pi-000: words'
ok   word 2: exit 101, '12-mixed-pi-000: words'
ok   word 3: exit 101, '12-mixed-pi-000: words'
ok   word 4: exit 101, '12-mixed-pi-000: words'
ok   word 5: exit 101, '12-mixed-pi-000: words'
ok   word 6: exit 101, '12-mixed-pi-000: words'
ok   word 7: exit 101, '12-mixed-pi-000: words'
ok   word 8: exit 101, '12-mixed-pi-000: words'
ok   word 9: exit 101, '12-mixed-pi-000: words'
ok   word 10: exit 101, '12-mixed-pi-000: words'
ok   word 11: exit 101, '12-mixed-pi-000: words'
ok   word 12: exit 101, '12-mixed-pi-000: words'
ok   word 24: exit 101, '24-mixed-pi-000: words'
ok   a word dropped: exit 101, '12-mixed-pi-000: words'
ok   insert position: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert device: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert device count: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert sequence: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert SeedBook number: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert word: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert face cell: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert face letter: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert mirror partner dropped: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert mirror partner changed: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert lighter mark dropped: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert lighter mark on face 4: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert word cells: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert faces reordered: exit 101, '12-mixed-pi-000: inserts line 2'
ok   insert blank face: exit 101, '12-mixed-pi-000: inserts line 6'
ok   insert blank face marked lighter: exit 101, '12-mixed-pi-000: inserts line 6'
ok   insert line dropped: exit 101, '12-mixed-pi-000: inserts'
ok   insert device, 24 words: exit 101, '24-mixed-pi-000: inserts line 13'
ok   insert sequence, 24 words: exit 101, '24-mixed-pi-000: inserts line 13'
ok   seed bits: exit 101, '12-mixed-pi-000: entropy_hex'
ok   seed bits, 24 words: exit 101, '24-dice_only-phone-000: entropy_hex'
ok   unknown expect key: exit 101, '12-mixed-pi-000: not compared: ["zz_extra"]'
ok   expect key removed: exit 101, '12-mixed-pi-000: bucket is not recorded, or was compared twice'
ok   stub one byte short, check path: exit 101, '12-mixed-pi-001: start_check: Source(Os)'
ok   stub one byte short, dice-only check path: exit 101, '24-dice_only-phone-009: start_check: Source(Os)'
ok   stub one byte short, mixed skip path: exit 101, '12-mixed-pi-000: commit: Source(Os)'
ok   first ceremony's stub one byte short: exit 101, '12-mixed-pi-005: first start_check: Source(Os)'
ok   stub label changed: exit 101, '12-mixed-pi-001: c_hex'
ok   refusal error: exit 101, '12-mixed-pi-short: error'
ok   refusal step: exit 101, '12-mixed-pi-short: step'
ok   refusal roll on finish: exit 101, '12-mixed-pi-short: roll'
ok   refusal error, 257: exit 101, '12-mixed-pi-257: error'
ok   refusal step, 257: exit 101, '12-mixed-pi-257: step'
ok   refusal roll, 257: exit 101, '12-mixed-pi-257: roll'
ok   refusal error, bad face: exit 101, '12-mixed-pi-face-0: error'
ok   refusal roll, bad face: exit 101, '12-mixed-pi-face-0: roll'
ok   refusal error, 98-roll restart: exit 101, '12-mixed-pi-restart-98: error'
ok   refusal key removed: exit 101, '12-mixed-pi-short: roll is not recorded, or was compared twice'
ok   refusal rolls core accepts: exit 101, '12-mixed-pi-short: core accepted the rolls'
ok   98-roll restart without its first ceremony: exit 101, '12-mixed-pi-restart-98: core accepted the rolls'
ok   verdict refused -> warned: exit 101, '12-mixed-pi-short: verdict'
ok   verdict warned -> refused: exit 101, '12-dice_only-pi-short: verdict'
ok   verdict input-refused position: exit 101, '12-mixed-pi-face-0: verdict'
ok   verdict diverges -> refused: exit 101, '12-mixed-pi-restart-98: verdict'
ok   diverges: the verifier's words: exit 101, "12-mixed-pi-restart-98: the verifier's words"
ok   diverges: the verifier's seed bits: exit 101, "12-mixed-pi-restart-98: the verifier's seed bits"
ok   a deleted ceremony: exit 101, 'assertion `left == right` failed: 12-mixed-pi-: the case count'
ok   a deleted refusal: exit 101, 'assertion `left == right` failed: the refusal count'
92 mutations, 0 unexpected
```

**Deviations from the plan**, each with why:
- agreement.json is 4,155,350 bytes at fcb3481 (4,155,498 after 9a3902a; 851 KB gzipped), not the planned 2-2.5 MB.
  JSON escapes each braille cell as `\u28xx` (6 bytes), which keeps generated files ASCII as braille.json is; the
  insert lines are 2.2 MB of it. UTF-8 would give about 3 MB and break the ASCII rule for this one file.
- Commit 5b (df1c053) is not in the plan's first commit order. The stage-A review (F10) found clipboard and network
  routes the planned lists missed, and 5b completed Q23's lists: `socketserver`, `urllib3`, `nntplib`, `smtpd`,
  `asyncore`, `asynchat`, `wsgiref`, `multiprocessing.connection` and `logging.handlers`; the `clipboard` module,
  `win32clipboard`, `wl-paste`, `Get-`/`Set-Clipboard`, `clip.exe`, "the clipboard", any `.clipboard`,
  `to_`/`read_clipboard` and `selection_get`. The cost: an import of any name `connection` or `handlers`, and the
  words "the clipboard" in a `.py` file, are gate hits.
- `_socket` and `_ssl` joined the network list (5cc295d), beyond the list Q23 approved: they are the C modules behind
  socket and ssl, and `import _socket` gives the whole socket API.
- Q19 (c)'s layout entry in build-plan.md wraps over three rows of the tree, not one line, since one line would be
  about 170 characters against 105 elsewhere in the block (5d222f5).
- The split was a pure move but for one code string: ed25519_secret's ValueError text names vectorgen.py. Check 10
  raises and catches it, and no passing run prints it (99edb77). kcr.json's and backup.json's descriptions say
  "verify.py's verifier" and "reader" rather than "its own", since those stayed in verify.py (76dd1fb).
- Group 1's split item names CI green on 99edb77 in its proof. CI runs only on pushed heads, so the item is ticked
  on 86c4c0d (run 38061106528), the first pushed head that holds 99edb77, with 99edb77's local proof. The owner may
  read the item strictly and untick it.
- SOURCES.md's records of pre-split work name code by the file that holds it now, under one note (0610f3e), rather
  than per-line "then in verify.py" wording.
- Check 12's rule (a) is stricter than planned. Every dunder name but `__name__` and `__doc__` is banned
  (`__loader__.get_data` reads files), and a module name used other than to take a recorded attribute fails (no
  aliasing). `os.spawn` and the file-by-path events are audit failures, and the name `type` is banned (8ced14f).
- `known_answers` takes the table (`known_answers(KNOWN_ANSWERS)`, 2db1b6f), so that the sweep can change each value,
  and `InputRefused` carries a third field, the fixed rule text (3727711). The plan writes `known_answers()` and
  `InputRefused(field, position)`.
- vectorgen's `load_verify` takes no path: check 12's in-process parts (the sweep, the input cases, the tie and the
  in-process run) call tools/verify/verify.py even under `--verify-py`, and the audited command runs hold the copy
  instead (stage-A note 2, not applied as written).
- verify.py is no longer pure ASCII: the braille cells in `KNOWN_ANSWERS` are UTF-8 characters, as in vectorgen, so
  the shipped file's SHA-256 covers them.
- Check 13 does more than the plan lists, because the stage-B and stage-C reviews showed that a re-baseline could
  remove the proof of byte equality alone. It works out each refusal's verdict apart from the generator, holds the
  quota apart from verify.py's `DICE`, pins each refusal to its boundary and every case to the planned mix, ties
  values to their definitions and inserts to braille.json, refuses a changed D, and holds each rule to a control. It
  runs Coldcard's scripts on 74 cases (plan: about 70).
- agreement.json's refusals keep core's part in `expect` and verify.py's in a separate `verifier` object, and a
  ceremony's `expect` holds null where a value does not apply, so core's completeness rule covers only what core can
  compare. Core has no accessor for E, n or G, so agreement.rs takes the seed bits from the SeedBook numbers and n
  from core's own check URL, and checks G by its being accepted (the plan's "G accepted by core").
- agreement.rs adds two comparisons the plan does not list: each refusal's verifier verdict against core's error,
  mode and restart, and each 98-roll restart's inputs run as a first ceremony, which must give the verifier's words.
- Commit 11 is two commits: a45c2d0 (the case-mix pin, a vectorgen change inside group 5) and 6dcce94 (the canaries).
- agreement-core builds in `target/canary-agreement`, not the planned `target/canary-real`, and touches the copy's
  tests/agreement.rs first. Cargo took a copy's test binary as `Fresh` across trees copied with their mtimes kept,
  reproduced in 6dcce94's proof.
- vectorgen imports more of the standard library than the plan's list (ast, pty, runpy, sysconfig): getpass, io,
  select, signal and time at top level, importlib.util for the load by path, and shutil in the refused-actions
  control; runpy and sysconfig only in the audit harness's child. The New dependencies line lists them (5100b6f).
- Check 12 makes runs beyond the plan's list: Ctrl-C in a pty (exit 130), the audited stdin-closed run (exit 70),
  the five argument runs and the typed forms (the stage-D review), and controls on the leak rule, the locale run
  and the in-process run.
- The banner, the notes, 2.585 bits per roll and the stderr lines are also held in vectorgen (`KNOWN_ANSWER_RUN_*`,
  `STDERR_*`), apart from `render`, so changing a note or prompt means editing verify.py, its `run` literal and
  vectorgen.
- F15 part 5 is not covered. A getpass call without `stream=sys.stderr` would put the prompt on /dev/tty. In a pty
  run stderr and /dev/tty are the same terminal, so telling them apart needs a pty run with stderr redirected and
  read as a second stream. Where the prompt appears leaks nothing.
- The dice pty run still types the plan's `123` and `456`, which no 12-roll leak window can see; the transcript pin
  catches an echo of them instead.
- Under `--verify-py` the pty runs wait for tools/verify/verify.py's prompt texts, so a copy with other prompts
  fails only after the 60 s per-run timeout. No canary changes the prompts.
- CLAUDE.md Commands also names the canary count (61), which the plan's Commands item did not list. vectorgen's
  testing-only `--verify-py` and `--check` are not listed, like `--vectors-dir`.
- Text typed before the first prompt is echoed by the terminal and then dropped (8a1b0c6), so the guide says to wait
  for each prompt. Q20's recorded answer is unchanged; it holds for a paste at C's prompt.

**CI.** Each stage was pushed and Entropy CI ran on the PR head (`pull_request`, PR #5). The Vercel check is not
required and fails on every PR; the owner said to ignore it.
- Stage A, 86c4c0d: run 38061106528 (2026-10-10, 14:48-14:52 UTC), success, all 14 Entropy check runs passed. It
  was the first GNU grep run of the gate's Python patterns.
- Stage B, 9301be3: run 38075212741 (2026-10-10, 18:17-18:22 UTC), success, all 14 passed. It was the first Linux
  run of check 12's audit harness.
- Stage C, 0d2ff75: run 38106150762 (2026-10-11, 02:45-02:48 UTC), success, all 14 passed. It was the first CI run
  of check 13 and core/tests/agreement.rs.
- Stage D, 5100b6f: run 38115700518 (2026-10-11, 05:43-05:51 UTC), success, all 14 passed. It was the first Linux
  run of check 12's pty transcripts and of its audited exit-70 run. Seen at 06:00 UTC with `gh pr checks 5` and
  `gh run list`, then read from the run's jobs and log:

```text
gates (banned APIs, verifier, canaries)  8m07s  banned-api-check: clean, 162 files scanned; vectorgen.py --selftest
                                                (ubuntu-24.04's python3): 13 ok lines, selftest passed: 13 checks
                                                (22 s); gate selftest: 346 passed, 0 failed; canaries (414 s): PASS
                                                for agreement-core, the 9 tamper runs (vectors-tamper-agreement.json
                                                among them) and verifier-import, -echo, -echo-upper, -tty and -reach;
                                                PASS: all 61 checks ran
verifier (python 3.9)                    1m04s  Python 3.9.6 (macOS); 13 ok lines, selftest passed: 13 checks (56 s)
test                                     2m58s  default: lib 161 passed, 1 ignored; ceremony 5, kat 7, kcr_release 3,
                                                os_source 2, typestate 1, vectors 4. test-sources: lib 189 passed,
                                                1 ignored; agreement 9 passed in 5.22 s; ceremony 5, check_flow 6,
                                                error_injection 11, kat 7, kcr 3, no_panic 9, no_secret_text 5,
                                                os_source 2, panic_wipe 4, source_substitution 5, typestate 1,
                                                vectors 4
coverage (core, 95% of lines)            2m51s  agreement 9 passed in 7.18 s; TOTAL regions 96.87%, functions
                                                96.27%, lines 8272, missed 216, 97.39%
age-interop (age 1.1.1)                  1m10s  age 1.1.1-1ubuntu0.24.04.3; three ok lines; 17 of the 17 armor cases
                                                refused
cross (6 targets)                  1m39s-2m41s  each: clean, 2 file(s): no marker, no test key, no other RNG symbol;
                                                getrandom (Pi, Android) or _CCRandomGenerateBytes (iOS) imported
lint (fmt, clippy) 31s; supply-chain (deny, audit, vet) 39s; changes (Entropy/ or this workflow) 6s: pass
```

Against the M1 baseline run 38041799043 (gates 3m36s, verifier (python 3.9) 26 s, test 4m55s), gates grew by
4m31s, nearly all of it the canaries step, and stays inside group 8's 10 minutes (the job's timeout is 30).

**Ticked in this commit** (each with its Proof line above): group 0's answers and doc edits, and its baseline;
group 1's split; group 4's `verification_run`; group 7's check 12 command runs; group 8's CLAUDE.md Commands;
Verification "Gate, part 2", "Deliverables", "Release form", "Rules for the shipped file" and "The banned-API gate".
After the CI look above (run 38115700518 complete and green), also: group 6's `core/Cargo.toml`; group 8's
canaries, CI and runtime budget; group 9's Review; and Verification "Gate, part 1", the three matrix rows, "The
split changed no M1 output", "Runtime ... every CI job green" and "Definition of done".

**Still unticked**, with what each waits for:
- None in M2. Every plan and Verification item of the M2 section is ticked with its proof. What remains is the
  owner's approval of the gate below.

### M2 gate status: MET, approved by the owner and merged (PR #5, 2026-10-11)
The gate in docs/build-plan.md: "Verifier and core agree on 1,000 generated cases, including seal codes and braille;
dice-only output matches Coldcard `rolls.py`".
- Agreement. core/tests/agreement.rs replays all 1,000 ceremonies and the 28 refusals of vectors/agreement.json through
  core's public session API under `test-sources`, and compares every key of each case's `expect`, each exactly once:
  C, D, the seed bits and every word; the seal (grouped code, tag, Seal ID and its braille, lookup prefix, bucket,
  grid, colour, re-check URL), both on Sealed and from `seal_from_mnemonic`; n, the check URL, G accepted and the
  next-value wrong G refused as exactly `WrongCode`; the register URL and Seal ID; the collision report on the 8
  restarts; and every braille insert field (position, device and count, sequence, SeedBook number, word, each face's
  cell, letter, mirror partner, lighter mark and dots, and the word's cells), read from core's accessors. These are
  verify.py's values but n, which is the stub's, and each refusal's error, step and roll, which vectorgen works out.
  Core stops each of the 28 refusals with the recorded error at the recorded step. Of each refusal's `verifier`
  object it compares the verdict (8 refused, 8 input-refused, 8 warned, 4 diverges, Q21), each input-refused
  position with core's roll, and for the four 98-roll restarts the words and seed bits. It does not compare the
  refusal and warning texts or the warned cases' words and seed bits, which core has nothing to compare with; check
  13 holds the warned cases' words and seed bits to Coldcard's scripts. At 5100b6f it passes 9/9, and the
  agreement-core canary fails naming `24-mixed-pi-083: seal_tag_hex`. At 1f86f2c each of 92 planted changes failed
  naming its case and field (core is unchanged since, and agreement.json changed only in its spec line). On the
  verifier's side, check 13 regenerates agreement.json byte for byte on 3.12.5 and 3.9.6 and holds it to rules a
  re-baseline cannot remove, each with a control.
- Coldcard. Check 13 runs Coldcard's hash-pinned `rolls.py` and `rolls12.py` on 74 dice-only cases (64 ceremonies and
  the 10 dice-only refusals with valid faces, 49 to 257 rolls), and each prints exactly the case's `entropy` line and
  words. Check 4 runs them on rolls.json and keepcrypt.json's dice-only cases, and check 12's lone `dice` prints
  Coldcard's words for `123456` at both lengths.
- CI. Run 38115700518 on 5100b6f, the PR head, is complete and green: all 14 Entropy check runs pass (the Vercel
  check, not required, fails as on every PR). Its test and coverage jobs run agreement.rs (9/9), its gates and
  verifier (python 3.9) jobs run check 13 on ubuntu-24.04's python3 and macOS's 3.9.6, and gates runs the
  agreement-core and agreement.json tamper canaries. The commit that adds this Review changes only this file; CI
  runs on it after the next push.
- Every M2 plan and Verification item is ticked with its proof, every high and medium review finding is fixed,
  and no new dependency, CI job or required context was added.
- Open items, all low; none is part of the gate:
  - low: F15 part 5, getpass's prompt stream (deviations above).
  - low: `gates` takes 8m07s of group 8's 10-minute budget, so the next canaries need the budget re-planned.
  - low: no test pins the length and alphabet guards of verify.py's `check_url` and `register_url` (stage-B finding
    7's nonce-length mutant, and its fix report). No M2 input reaches them, so no output can change.
  - low, for the owner: gate routes outside the completed Q23 lists (stage-B commit 5b report): `import
    logging.config` and `multiprocessing.managers`, which reach sockets; a dotted import ending in a banned name,
    such as `gevent.socket`; tkinter's `selection_own` and `tk.call('clipboard', ...)`; PowerShell's `gcb`/`scb`;
    JXA's `theClipboard`; and pandas' `clipboard_set`. Check 12's audit catches any socket or process in verify.py.
  - low, for the owner: plan text the fixers changed after "approve all": the Spec values guard, group 2's lists
    (`_socket`, `_ssl` and 5b's names) and residuals, group 1's grep, and group 3's rule (a) with commit 6's change to
    `BackupRefused`.
  - low: the guidance for M3, M5 and M6 should carry the same caveat as 8a1b0c6: wait for each prompt.
  - low: agreement.json's `description` and core/tests/agreement.rs's header still say the file comes from
    verify.py's `verification_run` and `render`; the spec's `expect` entry names each source (9a3902a).
  - low: check 12's keepcrypt.json tie still reads verify.py's `DICE`. Check 13's `AGREEMENT_QUOTA` and core's
    dice.rs pin the quota.
  - low: 22883dc's commit body says "14 lines" and "163 files". History is not rewritten; 86c4c0d and this file
    correct them (11 lines; 160 files from a clean checkout).
  - M1 owner items 13 and 14 (low) are still open and do not touch M2.
- Per CLAUDE.md, M3 does not start until the owner approves.

**Approved and merged (2026-10-11).** The owner approved the gate ("approve m2"). CI on 60d6ebb, the final head,
passed all 14 required Entropy check runs (the Vercel check, not required, failed as on every PR). PR #5 was marked
ready and merged with a merge commit, 156c8ef ("Merge Entropy M2: offline verifier (tools/verify) (#5)"), and
`m2-verifier` was deleted. The owner then asked for the M3 plan ("yes"); M3 work happens on `m3-pi-sim`.
