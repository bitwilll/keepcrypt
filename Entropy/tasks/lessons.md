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
