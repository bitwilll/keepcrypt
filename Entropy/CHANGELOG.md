# Changelog

Each release's section is copied into its release notes by `scripts/release-notes.py`, which
fails when the tag's version has no section here. Versions before 1.0.0 are pre-releases: not for
real funds until the independent audit's fixes are published (docs/build-plan.md, "Before 1.0";
SECURITY.md).

## 0.1.0

The first tagged pre-release. **Do not use it for real funds.** It exists so the audit and
outside builders have one fixed version to read, rebuild and test.

- **Core (`core/`):** one source of OS randomness, mixed into a 256-bit pool with SHA-512 and
  health-tested; the dice commitment C, the seed E, BIP39 words (12 or 24), the collision seal,
  the go-ahead check, the age v1 backup (scrypt, generated 8-word passphrase), the watch-only
  export and the SeedBook braille inserts; typestate order enforced at compile time.
- **Offline verifier (`tools/verify/verify.py`):** a single Python file that checks seeds, seals,
  backups and registry snapshots against the same vectors. Its SHA-256 is in the release notes.
- **Raspberry Pi image:** Buildroot 2026.08, built twice in CI and compared bit for bit; the
  firmware runs the whole ceremony on the Pi's own screen and keys.
- **Android app:** no network permission, protected windows, the same core through one FFI call.
  The release APK is signed offline by the project's key.
- **iPhone app:** the same core through a C boundary, capture-state redaction and no networking
  code. Not reproducible (the App Store re-signs it); source and build steps only.
- **Every release ships** SHA-256 sums signed offline, an SBOM per artifact (CycloneDX), this
  changelog and the command that reproduces each artifact.
