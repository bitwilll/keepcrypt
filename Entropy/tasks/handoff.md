# Handoff: M5 (Android), Stage U-5, 2026-11-01 06:50 UTC

A new session starts here. CLAUDE.md's workflow still comes first: read `tasks/lessons.md`, then M5 in
`tasks/todo.md` (Stage U's plans are under "Stage U", the proofs under M5's Review). This file only says where
things stand and what comes next.

## Where things stand

- Branch `m5-android`, draft PR https://github.com/bitwilll/keepcrypt/pull/9. Never push to `main`.
- Latest commit: U3h-c (M5-83): every pad key is its whole cell, 48 dp high or more, at most six columns; AwayTest
  gathers SystemUI's back gesture facts before it fails. Every CI run of the PR is "Entropy Android"
  (`.github/workflows/entropy-android.yml`).
- Stage U-5 is under way, without a check-in (M5-72 (h): U-1 to U-5 run without one; U-6 waits for the owner's
  answers to Q77-Q85). Its plan, item by item, is in todo.md's "U-5's plan":
  - **Done:** U1h, U1, U2h (DeviceChangeTest), U2i (DoubleTapTest and the press guard, M5-79), U2j (KillTest, M5-80),
    U3h-a (KitColorsTest, DocsTextsTest).
  - **U2l proven on both levels** at d09eb7a (run 41279169126): ScanRefusedTest, and IdleClockTest on API 36 (cover
    30.25 s, warning 540.4 s, wipe 600.5 s). Tick it once its registry jobs are green.
  - **U2k (AwayTest):** both screen-off tests green on both levels; the back gesture under gesture navigation brings
    no Back from the shell's swipe (navigation_mode 2, two runs). The head's run prints SystemUI's
    EdgeBackGestureHandler facts and tries a UiAutomation swipe (M5-83 (d)): decide the fix from that probe line.
  - **U3h-b:** the layout check found the dice keys at 46 and 40 dp; fixed at the head (M5-83). The walk stopped at the
    dice, so later screens are checked for the first time in the head's run.
- Budgets (M5-30, measured + 25%): journeys 27/26, ui 26/27 minutes; capture 30/30 and registry 30/40 stay "measuring"
  until their first green run with every test (registry at d09eb7a: API 31's job 17.5 min, API 36's 28 min).

## Next steps, in order

1. Read CI at the head: both capture jobs' layout lines ("controls of 48 dp or more" on every screen, or the next
   finding, a finding about the app, never a reason to relax 48 dp); AwayTest's probe line "SystemUI's back gesture
   handler: ...", and whether the UiAutomation swipe brought Back.
2. Fix from those facts, then tick U2k, U2l, U3h-b, U3h and U2 once green; budget capture and registry by M5-30.
3. At U-5's head: three independent reviews, their verified findings fixed, the suite, CI read; then report to
   the owner. U-6 (U2m, U3i-U3k, U3n) waits for Q77-Q85.
4. If the owner wants APKs of the head, rebuild them (the ones below predate the press guard and M5-83).

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
- Do not decide Q77-Q85, touch `main` or merge. A lead decision gets a dated M5-n entry in todo.md (last: M5-83).

## Local commands (this container; `ANDROID_HOME=/root/android-sdk` must be set)

```bash
cd /home/user/keepcrypt/Entropy
sh scripts/android-emulator.sh --selftest            # 64 passed
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
