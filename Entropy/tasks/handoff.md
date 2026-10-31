# Handoff: M5 (Android), Stage U-5, 2026-10-31 22:05 UTC

A new session starts here. CLAUDE.md's workflow still comes first: read `tasks/lessons.md`, then M5 in
`tasks/todo.md` (Stage U's plans are under "Stage U", the proofs under M5's Review). This file only says where
things stand and what comes next.

## Where things stand

- Branch `m5-android`, draft PR https://github.com/bitwilll/keepcrypt/pull/9. Never push to `main`.
- Latest commit: the one that adds this file, on top of `97ce674` (U2h, DeviceChangeTest) and `e7dbf6a` (U1h,
  MixedJourneyTest). Every CI run of the PR is "Entropy Android" (`.github/workflows/entropy-android.yml`).
- Stage U-4 is closed: CI at `4a1cc07` (run 41211393696) was green in every job, U1b-U1g proven on API 31 and 36.
- Stage U-5 is under way, without a check-in (M5-72 (h): U-1 to U-5 run without one; U-6 waits for the owner's
  answers to Q77-Q85). Its plan, item by item, is in todo.md's "U-5's plan":
  - U1h (MixedJourneyTest, a mixed 24-word seed to Finish through the UI alone; journeys part): written and pushed,
    **not yet proven on an emulator**. Its first run (41244825682 at e7dbf6a) was cancelled by the push of this
    commit, by design: this commit's run holds it too.
  - U2h (DeviceChangeTest: rotation, font scale and night mode, each and back, on the dice, the code entry, the
    words' gate and a words page; registry part, after LifecycleTest, before the killed CrashTest): written,
    committed in `97ce674`, **not yet proven on an emulator**.
  - U2i, U2j, U2k, U2l and U3h: planned, not started.
- The registry and journeys jobs' timeouts are 30 minutes, their measuring run (M5-76 (f), M5-77 (a) and (b)).

## Next steps, in order

1. Read CI at this commit once its run ends (about 35 minutes after the push). For each of the eight emulator
   jobs record its result and time (job start to end) in todo.md's Review under the U1h and U2h proofs, with
   the pass lines of MixedJourneyTest (journeys jobs) and DeviceChangeTest (registry jobs, and its six probe
   lines "...: six changes, each a new activity with everything kept, in N s").
   - Both journeys jobs green: tick U1h, then U1 (its last combination). Both registry jobs green: tick U2h.
   - Budget the journeys and registry jobs by M5-30 (measured time + 25%, rounded up) in the workflow's matrix
     and its Budget comment, as the earlier entries there do.
   - A red job: diagnose it from its lines (`mcp__github__get_job_logs`, or download the log and read it); never
     rerun to green; fix at the root, then a new push. DeviceChangeTest's most likely device surprises: a
     rotation that does not recreate on API 36 (the test then fails "a new MainActivity resumed"), or a change
     that alters the state (a screen's first composition calling the model). Either one is a finding about
     the app, not the test; record it and fix the app or re-plan, never relax the check.
2. U2i (DoubleTapTest, ui part), U2j (probe run, then KillTest), U2k, U2l, U3h, as their items say. Each adds
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
sh scripts/android-emulator.sh --selftest            # 59 passed at 97ce674
sh scripts/android-local.sh --selftest               # 47 passed
sh scripts/android-instrument.sh --selftest          # 50 passed
sh scripts/banned-api-check.sh                       # clean, 404 files
ANDROID_HOME=/root/android-sdk sh scripts/android-rust.sh shipping
ANDROID_HOME=/root/android-sdk sh scripts/android-rust.sh withTestRegistry
ANDROID_HOME=/root/android-sdk sh scripts/android-gradle.sh --dependency-verification strict :app:assembleShippingRelease :app:assembleWithTestRegistryRelease :app:assembleShippingReleaseAndroidTest :app:assembleWithTestRegistryReleaseAndroidTest
```

Reading CI: load `mcp__github__actions_list`, `mcp__github__actions_get` and `mcp__github__get_job_logs`
through ToolSearch, list the runs of `entropy-android.yml` on branch `m5-android`, then the run's jobs.

## APKs at 97ce674

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
- A scheduled reminder (`trig_01AhfF11hMmC7ez15VXRZyVM`, 22:19 UTC) fires into the old session only; ignore it.
