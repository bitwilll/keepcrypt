# Making a release

This is the owner's procedure for a KeepCrypt-Entropy release (tasks/todo.md, M7 items B3 and B4;
Q100, Q103, Q109, Q110; docs/build-plan.md, "Release, reproducible builds and audit"). CI builds,
scans and hashes every artifact, but it never signs and never publishes. The owner checks the
artifacts against a second build, signs offline and makes the release from their own machine.

Versions before 1.0.0 are pre-releases: marked as such on GitHub and in the notes, and not for real
funds until the independent audit's fixes are published (SECURITY.md).

## Once: the release key

The release key signs `SHA256SUMS` with minisign (Ed25519). Make it on an offline computer and
keep the secret key and its password offline, never on a networked machine, never in CI.

```bash
minisign -G -p keepcrypt.pub -s keepcrypt.key
```

Commit only `keepcrypt.pub`, as `Entropy/release/keepcrypt.pub`, and print its key ID in
SECURITY.md. The secret key needs a backup as carefully kept as the key itself: without it, no
later release can be signed under the same key.

The Android release key (an apksigner keystore) is kept the same way, offline. Its certificate's
SHA-256 goes into SECURITY.md beside the minisign key ID, so users and F-Droid can check it.

## 1. Before the tag

- The milestone's gate is approved and its branch merged to `main`; all four workflows are green
  on `main`'s head commit.
- `Entropy/CHANGELOG.md` has a `## X.Y.Z` section for the version (release.yml refuses a version
  without one).
- Every site names the version: `scripts/check-version.sh` prints "every site names X.Y.Z".
- The "before every release" drills of the build plan's test matrix are recorded in
  tasks/todo.md: the duplicate-seed drill, the watch-only import into Sparrow and Bitcoin Core, and
  the metal read-back drill.

## 2. The tag

From the merged `main`, on the commit the gate approved:

```bash
git tag -a vX.Y.Z -m "KeepCrypt-Entropy X.Y.Z"
git push origin vX.Y.Z
```

The tag starts three runs on the same commit:

| Workflow | Its artifacts |
| --- | --- |
| Entropy Pi image | the image (leg a; legs a and b must agree), `pi-image-release-files`: the image's SBOM, Buildroot's legal-info manifest, `SHA256SUMS` |
| Entropy Android | `android-apks`: `app-shipping-release-unsigned.apk`, the APK's SBOM, `SHA256SUMS` (the CI-signed APKs in it are signed with a throwaway key: never release them) |
| Entropy release | `release-source-files`: the workspace SBOM, `verify.py`, `RELEASE-NOTES.md`, `SHA256SUMS` |

All three must be green, and the release run's first step must say the tag is `v` and the
workspace version. Artifacts are kept 14 days. Download them signed in to GitHub, from each run's
page or with `gh`. The image is uploaded as the raw file, which `gh run download` cannot unpack,
so fetch it by its artifact ID:

```bash
gh run download RUN_ID --repo bitwilll/keepcrypt --name pi-image-release-files
gh api repos/bitwilll/keepcrypt/actions/artifacts/ARTIFACT_ID/zip > image.zip
```

## 3. The second build

Never sign what only one machine built.

- **Pi image:** CI's two legs already agree. Rebuild it once more yourself, or take the outside
  builder's posted SHA-256 (Q103), with the command in `RELEASE-NOTES.md`. The image's SHA-256 must
  equal its line in the Pi run's `SHA256SUMS`.
- **Android APK:** rebuild the unsigned APK from the tag with the command in `RELEASE-NOTES.md`
  and compare its SHA-256 with CI's `app-shipping-release-unsigned.apk`. Once F-Droid lists the app,
  its rebuild counts too (Q103).
- **verify.py:** `shasum -a 256 Entropy/tools/verify/verify.py` from the tag's checkout equals the
  hash in `RELEASE-NOTES.md`.

If any hash differs, stop: nothing is signed until the cause is found and fixed.

## 4. Sign, offline

Copy the files to the offline computer. Sign the APK with the Android release key, then verify it
names that key and no other:

```bash
apksigner sign --ks keepcrypt-release.jks --out keepcrypt-X.Y.Z.apk app-shipping-release-unsigned.apk
apksigner verify --print-certs keepcrypt-X.Y.Z.apk
```

Put the release's files in one folder: the image, its `.sbom.cdx.json` and
`.legal-info-manifest.csv`; `keepcrypt-X.Y.Z.apk` and `app-shipping-release.sbom.cdx.json`;
`keepcrypt-entropy-X.Y.Z.sbom.cdx.json`; `verify.py`; `RELEASE-NOTES.md`. Write `SHA256SUMS` over
all of them, check that every file other than the signed APK has the same hash as in CI's
`SHA256SUMS`, then sign it:

```bash
sha256sum -- * > SHA256SUMS
minisign -Sm SHA256SUMS -s keepcrypt.key
minisign -Vm SHA256SUMS -p keepcrypt.pub
```

## 5. Publish

Back on a networked machine, review `RELEASE-NOTES.md`, then make the release as a draft and read
it before publishing:

```bash
gh release create vX.Y.Z --repo bitwilll/keepcrypt --draft --prerelease \
  --title "KeepCrypt-Entropy X.Y.Z" --notes-file RELEASE-NOTES.md \
  SHA256SUMS SHA256SUMS.minisig keepcrypt-pi-X.Y.Z-st7789-240x240.img \
  keepcrypt-pi-X.Y.Z-st7789-240x240.img.sbom.cdx.json \
  keepcrypt-pi-X.Y.Z-st7789-240x240.img.legal-info-manifest.csv \
  keepcrypt-X.Y.Z.apk app-shipping-release.sbom.cdx.json \
  keepcrypt-entropy-X.Y.Z.sbom.cdx.json verify.py
```

Leave out `--prerelease` from 1.0.0 on. Record the release in tasks/todo.md's Review: the tag, the
three run IDs, the signed `SHA256SUMS` and who made the second build.
