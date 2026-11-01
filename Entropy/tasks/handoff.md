# Handoff: M5 (Android), Stage U-5, 2026-11-01 00:30 UTC

A new session starts here. CLAUDE.md's workflow still comes first: read `tasks/lessons.md`, then M5 in
`tasks/todo.md` (Stage U's plans are under "Stage U", the proofs under M5's Review). This file only says where
things stand and what comes next.

## Where things stand

- Branch `m5-android`, draft PR https://github.com/bitwilll/keepcrypt/pull/9. Never push to `main`.
- Latest commit: U2i3 (the press guard timed from composition; run 41252883580 recorded). Every CI run of the PR
  is "Entropy Android" (`.github/workflows/entropy-android.yml`).
- Stage U-4 is closed: CI at `4a1cc07` (run 41211393696) was green in every job, U1b-U1g proven on API 31 and 36.
- Stage U-5 is under way, without a check-in (M5-72 (h): U-1 to U-5 run without one; U-6 waits for the owner's
  answers to Q77-Q85). Its plan, item by item, is in todo.md's "U-5's plan":
  - **Done:** U1h (and U1) at 4fe6231; U2h (DeviceChangeTest, 24 changes on four screens, both levels) at 72cd4fa.
  - **U2i (DoubleTapTest) and its fix, the press guard:** DoubleTapTest found Skip, Match found and Cannot check
    taking two steps (run 41247649576). The guard (`screens/.../PressGuard.kt`, wired in `Screens.kt`, M5-79) made
    DoubleTapTest green on both capture jobs at 72cd4fa, but its first timing (from the frame after the first)
    opened too late on CI's slow emulators and refused deliberate presses in FlowTest, BackupTest,
    SnapshotDrillTest and one JourneyTest journey. U2i3 times it from the view's composition (SideEffect) on the
    uptime clock touches carry (M5-79 (d)). **The head's run must show every journey green again and DoubleTapTest
    still green**; then tick U2i.
  - U2j, U2k, U2l and U3h: planned, not started.
- Budgets: capture 17/16 (run 41252883580), journeys 27/26, ui 26/27; registry stays 30 until a run measures it green.

## Next steps, in order

1. Read CI at the head once its run ends (about 35 minutes after the push). Record each emulator job's result and
   time in todo.md's Review under U2i3's proof.
   - Every job green: tick U2i; budget the registry jobs by M5-30 (measured time + 25%, rounded up).
   - A journey press still refused (a test failing with "timed out: the app shows <screen>" after a tap): check the
     time between the screen's composition and the tap; the guard must not be weakened below 300 ms. If CI's
     emulators need it, a test may wait for the guard (a documented wait in Ui.on), never skip it.
   - A red job: diagnose it from its lines (`mcp__github__get_job_logs`, or download the log and read it); never
     rerun to green; fix at the root, then a new push.
   - Watch API 31's capture job: in run 41247649576 its emulator went offline during ControlTest; at 72cd4fa it
     stayed up (an open item until it recurs or a few runs pass).
2. U2j (probe run, then KillTest), U2k, U2l, U3h, as their items say. Each adds
   its class to `scripts/android-emulator.sh` (the part's run, the pinned orders in `--selftest`, a
   `*-test-fails` case) and to `scripts/android-local.sh`'s run counts, then runs both selftests (lessons.md,
   2026-10-31).
3. At U-5's head: three independent reviews, their verified findings fixed, the suite, CI read; then report to
   the owner. U-6 (U2m, U3i-U3k, U3n) waits for Q77-Q85.

## Rules that bind every change here (in CLAUDE.md, todo.md's decisions and lessons.md)

- No secret in a log, probe or pass line, assertion message or UI Automator selector: no roll, letter, word,
  passphrase or state dump (M5-68 (e)). Compare in-process with `assertTrue(msg, a == b)`, never
  `assertEquals` on anything that may hold a secret (its failure prints both values).
- Journeys go through the UI alone: Public controls by accessibility click (`Ui.tapRolls`, `Ui.tap`), Protected
  pads by injected touches (`Ui.touch`, `Ui.touchOn`, never `UiObject2.click`, which logs its point); state is
  read in-process only to observe (M5-72 (a)).
- No new dependency without the owner. Test seeds only from `vectors/` (`GateSeeds.kt`).
- `sh scripts/banned-api-check.sh` before every commit that adds Kotlin; `--workflows ../.github/workflows`
  for workflow changes (both run from `Entropy/`).
- No emulator in this container: CI is the gate. A push cancels the PR's running run (concurrency).
- Every commit ends with the Co-Authored-By and Claude-Session lines the session's system reminder gives.
- Do not decide Q77-Q85, touch `main` or merge. A lead decision gets a dated M5-n entry in todo.md.

## Local commands (this container; `ANDROID_HOME=/root/android-sdk` must be set)

```bash
cd /home/user/keepcrypt/Entropy
sh scripts/android-emulator.sh --selftest            # 60 passed at f50a88b
sh scripts/android-local.sh --selftest               # 47 passed
sh scripts/android-instrument.sh --selftest          # 50 passed
sh scripts/banned-api-check.sh                       # clean, 407 files
ANDROID_HOME=/root/android-sdk sh scripts/android-rust.sh shipping
ANDROID_HOME=/root/android-sdk sh scripts/android-rust.sh withTestRegistry
ANDROID_HOME=/root/android-sdk sh scripts/android-gradle.sh --dependency-verification strict :app:assembleShippingRelease :app:assembleWithTestRegistryRelease :app:assembleShippingReleaseAndroidTest :app:assembleWithTestRegistryReleaseAndroidTest
```

Reading CI: load `mcp__github__actions_list`, `mcp__github__actions_get` and `mcp__github__get_job_logs`
through ToolSearch, list the runs of `entropy-android.yml` on branch `m5-android`, then the run's jobs.

## APKs at 97ce674 (before the press guard: U2i2 changes the app, so the head's APKs differ)

Built locally from `97ce674` (the app's own sources and native libraries are unchanged since 07:37, so Gradle
found the release APKs up to date) and signed with a throwaway key made for this purpose and then deleted
(as CI signs them; release signing is M7). Development builds, not for release. CI's `--apk` scan runs on its
own build of every push.

```text
42b0bb1f3b9e4dc7e0f8199b91f0e4f8250a0239bd44f3d208a636a8ecb6afad  keepcrypt-entropy-shipping-97ce674.apk
d2bc6b3f08fdfae5292f24928e210f7ecd436a48418a9f629f05932bfb2f2b95  keepcrypt-entropy-withTestRegistry-97ce674.apk
```

The test-registry APK trusts the test registry key and carries `KC_TEST_REGISTRY_DO_NOT_SHIP`: never hand it out
as a release. CI's build job uploads its own signed pair as an artifact on every run.

## Open items carried forward (todo.md has each in full)

- BackupTest's age -d logcat check failed once on API 36 (62f9c8c), passed on both levels since; the checker now
  prints each line's facts. Watch it in every journeys job.
- U1a8's close proof needs a run whose lines show "the dialog closed by"; U1a5's low-disk boot proof is owed.
- M5-54's residual halts; the j/h and w/r mirror flips are proven only in core's test.
- API 31's emulator went offline during ControlTest in run 41247649576, before any change of that run ran.
- Scheduled reminders of the old session fire into it only; ignore them.
