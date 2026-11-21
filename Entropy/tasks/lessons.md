# Lessons Learned

Claude Code: read this file at the start of every session. After any correction from the
owner, add an entry before continuing.

## Format

```markdown
## [Date or context]
**Mistake:** What happened
**Root Cause:** Why it happened
**Rule:** Concrete rule that prevents it next time
```

## Entries

## Spec verification before hand-off (2026-10-09)
**Mistake:** The braille section claimed 300 BIP39 words are one mirror-pair flip from another
word's first four letters; a script count of the official list gives 279.
**Root Cause:** The figure was written from an earlier rough count instead of being regenerated
by the checking script.
**Rule:** Every number in `docs/` that can be computed (counts, vectors, odds) comes from a script
committed under `vectors/` or `tools/`, and CI re-runs it.

## Spec verification before hand-off (2026-10-09)
**Mistake:** The seal tag was defined as SHA-256 over "the code's ASCII text", but the code is
displayed with grouping dashes; the vector only matches the 26 characters without dashes.
**Root Cause:** The display format and the hashed byte string were described in one phrase.
**Rule:** For every hash input, state the exact bytes (encoding, separators, case) and pin a vector.

## Spec verification before hand-off (2026-10-09)
**Mistake:** The snapshot freshness rule said "older than 30 days triggers a warning" for every
device, but the Pi Zero has no real-time clock.
**Root Cause:** A phone assumption was applied to the Pi without checking the hardware.
**Rule:** Check every time-based rule against each target: phones warn by date; the Pi shows the
date and asks the user to confirm it.

## Boot-path changes ship proven, not flagged (2026-10-15)
**Mistake:** Commit 15l removed the kernel's TTY layer, leaving the image with no console device, and the report to
the owner named "init copes with no console, but only your boot check proves it" as a risk for H1a to settle. The
owner had to ask for it to be fixed.
**Root Cause:** The removal was judged option by option (prompt visible, no selector, nothing uses it) without
asking what PID 1 and the firmware do on the first boot without a console; "the hardware test will tell" was
accepted for a question the pinned sources answer.
**Rule:** A change on the boot path (kernel options, init, the firmware's start-up, the image layout) ships only
with every failure mode it introduces resolved first: read the pinned source of each component that sees the
change, or take the conservative option, and put the proof in the commit and todo.md. A known unproven risk is never
handed to the owner's hardware session.

## Read-only means read-only on the owner's machine (2026-10-20)
**Mistake:** While researching Compose Multiplatform, a research agent ran `xcrun simctl list runtimes` on the owner's
Mac to read the simulator runtimes. It made Xcode install its simulator components (CoreSimulator 1174.9.2), a change to
the owner's machine nobody approved. The agent also ran `xcodebuild -version`, which changed nothing.
**Root Cause:** The research brief forbade edits to the repo but not tool invocations on the host, and Xcode's command-line
tools can install components as a side effect of a query.
**Rule:** Facts about a toolchain come from its published documentation, runner-image readmes or CI runs, never from
running its tools on the owner's Mac. No `xcrun`, `simctl`, `xcodebuild`, simulator, emulator, SDK manager or device
command runs on the owner's machine without the owner's yes, and every research brief says so.

## An intermittent failure's closing bar must need the fix (2026-10-31)
**Mistake:** The open item for UI Automator not seeing first_launch on API 36 was set to close "when a CI run passes
with U1a8 in". The fix only acts when the launcher's not-responding dialog comes up, and the failure comes and goes,
so a run without the dialog would have met that bar without exercising the fix at all (75349ee had passed with no
fix). The lead caught it when reading run 41187953910 at 29af0bc, which passed without printing a line of U1a8's.
**Root Cause:** The bar was written as "the job is green" rather than "the fix's own path ran and worked", and an
intermittent failure is green most of the time whatever the code does.
**Rule:** For an intermittent failure, the closing evidence is the fix's own path running on the real target (its
probe lines printed and the job passing), never a green run alone. A fix that cannot show itself acting gets a probe
line first, and the item names that line as its closing bar.

## A script that reads another's structure runs its selftest when that structure changes (2026-10-31)
**Mistake:** U1b added JourneyTest to android-emulator.sh's journeys part and U1e split it into a ui part with a new
gone: form, and each commit ran android-emulator.sh's and android-instrument.sh's selftests but not
android-local.sh's, which reads android-emulator.sh's part blocks and judges their runs. The kc37 local runner was
broken from U1b on (its selftest 4 failed); a U-4 review found it, not the lead.
**Root Cause:** The suite the lead ran per commit was the scripts the diff touched; android-local.sh was not in the
diff, and no CI job runs its selftest, so nothing failed.
**Rule:** A change to android-emulator.sh's parts, its classes or android-instrument.sh's run forms runs
android-local.sh --selftest too, and the commit's proof names its count. More generally: before a commit, list the
scripts that read the changed one (grep for its name and its markers) and run their selftests.

## A timing a fix rests on is measured, and an unseen cause is gathered, not guessed (2026-11-01)
- Mistake: the press guard's first two CI failures were each "fixed" by a timing story (U2i2, U2i3): that UI
  Automator's idle wait gave every press at least 500 ms after a screen appeared, and then that a late frame report
  opened the guard late. Neither was measured; the same presses failed at the same lines after the second fix, and the
  run that printed the guard's own facts showed the tests pressing under 300 ms after composition.
- Root cause: a claim about how long a test framework waits was taken as fact, and a deterministic failure was read as
  a timing one without a line that showed the timing.
- Rule: before a fix rests on a duration, a run or a test prints that duration. When a failure's cause cannot be seen in
  its lines, the next push adds the lines that show it (a probe of the deciding state), rather than a second guess.

## 2026-11-16: a message to a running workflow agent started a second copy of it
- Mistake: the lead sent SendMessage to a workflow's running implementer; it resumed a second instance of that agent,
  which worked the same tree and emulator in parallel, edited scripts/android-emulator.sh in place to run two methods
  while the first instance's ui run was executing it (sh reads a script as it runs: a bogus syntax error and a doubled
  result), and the workflow's own call hung.
- Root cause: the lead treated a running workflow agent as addressable; a send resumes a new instance instead.
- Rule: never message a running workflow agent; steer by stopping the workflow and relaunching with a note, or wait for
  its report. Never edit or restore a runner script while any run may be executing it: copy it elsewhere instead.


## 2026-11-17: a test-harness fix pushed without the banned-API gate turned Entropy CI red
- Mistake: 012aa5e7 named the text-input widget class in androidTest's Picker.kt; the gate's KtInput refuses it in every
  scope, so Entropy CI's gates job and every canary that counts hits failed (run 43917696155). The owner had to ask why.
- Root cause: only the emulator suites were run before the push; the Kotlin change was treated as test-only, outside
  the gate's reach, which it is not (KtInput, KtLog and others scan androidTest too).
- Rule: before every push that touches any source, scripts/banned-api-check.sh runs clean locally, and canaries.sh
  too when hit counts could move. A gate hit is fixed in the code, never by relaxing or dodging the rule.


## 2026-11-18: a push went out after a failing canary run, its exit code hidden by a pipe
- Mistake: before pushing U2f (63bb375c) the lead chained `scripts/canaries.sh 2>&1 | tail -1 && git push`; the
  canaries printed "FAIL: 92 checks ran; scripts/canaries.sh pins 102" and the push went ahead anyway. The failure was
  the lead's shell (no keg-only rustup on PATH); rerun with the toolchain PATH, all 102 checks ran.
- Root cause: a pipeline's exit status is its last command's (`tail`), so `&&` never saw the canaries fail; and the
  pre-push shell skipped the toolchain PATH prefix the local environment needs.
- Rule: a pre-push check's exit code is tested directly (no pipe after it, or `set -o pipefail`), and its output is
  read before the push; pre-push shells start with the toolchain PATH prefix. A push that slipped past a red check
  is reported to the owner as such, the check rerun, and the cause recorded here.

## 2026-11-21: a UI-test helper change broke the Shipping test build; only the hooks build was compiled
- Mistake: U3o (953746d2) made UITestSupport.swift's launchedToGoOffline, compiled in every configuration, call
  pressUntil, which JourneySupport.swift defines under `#if KC_TEST_HOOKS` alone. Both unit jobs failed at
  build-for-testing of KeepCrypt-Shipping ("cannot find 'pressUntil' in scope"); every journey job, a TestHooks build,
  was green.
- Root cause: the change was made for the journeys and checked against their build only; the UI-test target is
  compiled three times (Shipping, WithTestRegistry, TestHooks) and the pre-push checks build none of them.
- Rule: before pushing a change to any iOS source, UI tests included, build-for-testing runs locally for all three
  schemes (KeepCrypt-Shipping, -WithTestRegistry, -TestHooks) and each exit code is read.

## 2026-11-21: a CI diagnostic sampler died at its first tick and hid that it took nothing
- Mistake: U3n's sampler loop in entropy-ios.yml (journeys-6, the narrow iPhone) ran as `( while ...; done ) &` in a
  step whose shell is `bash -e -o pipefail`, and discarded sample's output. When the iOS 26.5 hang came back (run
  44925400647) the step printed no sample: the subshell had exited at the first `pgrep` that found no app.
- Root cause: a background subshell inherits errexit and pipefail; a command expected to fail (pgrep before the app
  starts) ended the loop, and with its output thrown away nothing said so. It was never run locally under the
  step's flags.
- Rule: a background loop in a CI step that tolerates failing commands sets `set +e` itself, logs each tick, and
  prints that log when the step fails; it is run locally under `bash -e -o pipefail` before it is pushed.


## 2026-11-22: a version bump left the APK scan's stand-ins at the old version; CI's gates job failed
- Mistake: B1 (694bcccf) moved the expected Android manifests to 0.1.0 but not scripts/testdata/apk/badging.txt and
  xmltree.txt, the --selftest-apk stand-ins for aapt2's output that are checked against those manifests. Every
  --selftest-apk case failed in CI's gates job (run 44937973859, at c6590498); the pre-push checks passed.
- Root cause: the version sites were found by searching for the old string outside scripts/testdata, on the view that
  fixtures do not carry the version; these two mirror an expected file and must. And the pre-push checks run
  --selftest but not --selftest-apk, which only CI ran.
- Rule: a fixture that stands in for a built artifact's output follows the expected file it is checked against, and
  scripts/check-version.sh lists every such site. Before pushing a change to any expected/ file, or to anything
  --selftest-apk or another self-test mode reads, run that mode locally.
