#!/usr/bin/env python3
"""A release's notes draft (tasks/todo.md, M7 item B3; docs/build-plan.md, "Every release ships"):
the version's CHANGELOG.md section, the files the release holds, the offline verifier's SHA-256, and
the command that reproduces each artifact. release.yml writes it on a v* tag; the owner reviews it,
adds the signed SHA256SUMS and makes the release (Q109; docs/release.md). It never signs.

Fails (exit 1) when the version is not X.Y.Z, the commit is not 40 hex digits, or CHANGELOG.md has
no "## X.Y.Z" section or an empty one. Usage:
  release-notes.py --version X.Y.Z --commit SHA --changelog CHANGELOG.md --verifier verify.py --out NOTES
  release-notes.py --selftest
Python 3.9+, standard library only, no network; run with python3 -I.
"""

import argparse
import hashlib
import re
import sys
import tempfile
from pathlib import Path


class Refused(Exception):
    pass


def section(changelog, version):
    """The text under "## version", up to the next "## " heading."""
    found = re.search(r"^## %s[ \t]*\n(.*?)(?=^## |\Z)" % re.escape(version), changelog, re.M | re.S)
    if not found or not found.group(1).strip():
        raise Refused("CHANGELOG.md has no section, or an empty one, for %s" % version)
    return found.group(1).strip()


def notes(version, commit, changelog, verifier_sha):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise Refused("version %r is not X.Y.Z" % version)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Refused("commit %r is not 40 hex digits" % commit)
    image = "keepcrypt-pi-%s-st7789-240x240.img" % version
    pre = version.startswith("0.")
    lines = ["# KeepCrypt-Entropy %s%s" % (version, " (pre-release)" if pre else ""), ""]
    if pre:
        lines += ["**Pre-release: do not use it for real funds** until the independent audit's fixes are "
                  "published (SECURITY.md).", ""]
    lines += [
        "Tag `v%s`, commit `%s`." % (version, commit), "",
        "## Changes", "", section(changelog, version), "",
        "## Files", "",
        "`SHA256SUMS` lists every file below and is signed offline with the project's release key "
        "(`SHA256SUMS.minisig`); check the signature first, then each file's SHA-256.", "",
        "- `%s`: the Raspberry Pi Zero SD card image, with `%s.sbom.cdx.json` (its SBOM) and "
        "`%s.legal-info-manifest.csv` (Buildroot's package and licence list)." % (image, image, image),
        "- `keepcrypt-%s.apk`: the Android app, signed by the project's key, with "
        "`app-shipping-release.sbom.cdx.json` (its SBOM)." % version,
        "- `keepcrypt-entropy-%s.sbom.cdx.json`: the SBOM of every shipped Rust crate." % version,
        "- `verify.py`: the offline verifier, SHA-256 `%s`." % verifier_sha, "",
        "## Reproduce", "",
        "From a clean checkout of the tag (`git checkout v%s`), in `Entropy/`:" % version, "",
        "- **Pi image** (Docker on any host; the pinned build container, `pi/os/container/Dockerfile`): "
        "`export KC_WORK=/kc-work && sh pi/os/container.sh build && sh pi/os/container.sh run make -C pi/os "
        "source image`, then `sha256sum /kc-work/out/images/%s` equals its line in `SHA256SUMS`. CI built it "
        "on two x86_64 hosts and an arm64 one and compared." % image,
        "- **Android APK, unsigned** (JDK 17, Android SDK and NDK r30 as `scripts/android-gradle.sh` "
        "checks): `sh scripts/android-rust.sh shipping && sh scripts/android-gradle.sh "
        "--dependency-verification strict :app:assembleShippingRelease`; the release APK is that "
        "unsigned APK signed with the project's key, so compare the files inside it, signature aside "
        "(`apksigner verify --print-certs` names the key).",
        "- **Offline verifier:** `shasum -a 256 tools/verify/verify.py` gives `%s`." % verifier_sha,
        "- **iPhone app:** not reproducible (the App Store re-signs it). Build it from this source with "
        "the Xcode version and steps in `mobile/ios/BUILDING.md`.",
        "",
    ]
    return "\n".join(lines)


def selftest():
    passed = failed = 0
    log = "# Changelog\n\n## 0.2.0\n\n- later\n\n## 0.1.0\n\n- first\n- second\n\n## 0.0.9\n\n- old\n"
    commit = "0123456789abcdef0123456789abcdef01234567"

    def case(label, run, want=None):
        nonlocal passed, failed
        try:
            got = run()
        except Refused as error:
            problem = None if want is None else "refused: %s" % error
        else:
            problem = "not refused" if want is None else (None if want(got) else "unexpected output")
        if problem:
            failed += 1
            print("FAIL %s: %s" % (label, problem))
        else:
            passed += 1

    good = lambda: notes("0.1.0", commit, log, "f" * 64)
    case("the version's section alone", good, lambda n: "- first\n- second" in n and "later" not in n and "old" not in n)
    case("a pre-release says so", good, lambda n: "(pre-release)" in n and "do not use it for real funds" in n)
    case("1.0.0 is no pre-release", lambda: notes("1.0.0", commit, "## 1.0.0\n- x\n", "f" * 64),
         lambda n: "pre-release" not in n.lower())
    case("the verifier's SHA-256 and the image name", good,
         lambda n: n.count("f" * 64) == 2 and "keepcrypt-pi-0.1.0-st7789-240x240.img" in n)
    case("refused: no section", lambda: notes("0.3.0", commit, log, "f" * 64))
    case("refused: an empty section", lambda: notes("0.1.0", commit, "## 0.1.0\n\n## 0.0.9\n- old\n", "f" * 64))
    case("refused: a version that is no X.Y.Z", lambda: notes("v0.1.0", commit, log, "f" * 64))
    case("refused: a short commit", lambda: notes("0.1.0", commit[:12], log, "f" * 64))
    case("a heading that only starts with the version is not it", lambda: notes("0.1.0", commit, "## 0.1.0-rc\n- x\n", "f" * 64))
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "NOTES.md"
        (Path(tmp) / "CHANGELOG.md").write_text(log, encoding="utf-8")
        (Path(tmp) / "verify.py").write_bytes(b"print('hi')\n")
        sha = hashlib.sha256(b"print('hi')\n").hexdigest()
        code = main(["--version", "0.1.0", "--commit", commit, "--changelog", str(Path(tmp) / "CHANGELOG.md"),
                     "--verifier", str(Path(tmp) / "verify.py"), "--out", str(out)])
        case("the command line writes the verifier's real SHA-256", lambda: (code, out.read_text(encoding="utf-8")),
             lambda r: r[0] == 0 and sha in r[1])
    print("release-notes selftest: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(prog="release-notes.py")
    for name in ("version", "commit", "changelog", "verifier", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        text = notes(args.version, args.commit, Path(args.changelog).read_text(encoding="utf-8"),
                     hashlib.sha256(Path(args.verifier).read_bytes()).hexdigest())
    except Refused as error:
        print("release-notes: refused: %s" % error, file=sys.stderr)
        return 1
    Path(args.out).write_text(text, encoding="utf-8")
    print("release-notes: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
