# Security policy

KeepCrypt generates Bitcoin seeds, so a bug here can cost people their savings. Please report
anything you find privately.

## Supported versions

None yet. KeepCrypt has no released version. Everything in this repository is pre-release and
must not be used to hold real funds.

## Reporting a vulnerability

Email: **admin@keepcrypt.com**

Never report a vulnerability in a public issue, pull request or discussion.

Please include:

- the component (`core/`, Pi firmware or OS image, Android, iPhone, registry, offline verifier)
  and the version or commit
- what goes wrong and what it lets an attacker do, especially anything that could weaken seed
  entropy, leak words, device leg D or a backup, or reveal words before the seal check passes
- steps to reproduce or a proof of concept, using only the test vectors in `vectors/`

Never send a real seed, real words or a backup that protects real funds.

## If an entropy bug is found

We will publish an advisory that lists:

- the affected versions and platforms
- how to tell whether a given seed is affected
- migration steps: make a new seed on a fixed version and move the funds to it

See `docs/build-plan.md`, "Release, reproducible builds and audit".

## Bug bounty

None before 1.0. A public bug bounty starts after 1.0; an independent security audit comes
before it.
