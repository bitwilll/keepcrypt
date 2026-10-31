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
