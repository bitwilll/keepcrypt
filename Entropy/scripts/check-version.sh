#!/bin/sh
# One version for the whole project (tasks/todo.md, M7 item B1; Q101): the workspace's, in
# Cargo.toml's [workspace.package], which every crate takes with `version.workspace = true` and
# Rust code reads with env!("CARGO_PKG_VERSION"), keepcrypt-ffi's and pi/app's created-by lines
# included. Every other place that names it must name the same one, exactly once where listed:
# - Android: both build.gradle.kts versionName, the expected manifests and --selftest-apk's stand-ins for
#   aapt2's output on them, HomeScreens.kt's APP_VERSION;
# - iPhone: Info.plist's CFBundleShortVersionString, the expected Info files, Texts.swift's
#   appVersion, and the tests that spell out About's line or the development-build line;
# - Pi: keepcrypt-pi.mk's version, the image name (pi/os/Makefile, genimage.cfg), the build path
#   of keepcrypt-pi (pi/os/Makefile, entropy-pi-image.yml, CLAUDE.md).
# Each crate's own manifest must take the workspace version. A site that is missing, doubled or
# names another version fails, by file and line. Adding a place that names the version is a
# reviewed change to SITES below.
# Usage: scripts/check-version.sh [ENTROPY_DIR]   (default: the current directory; the workflows
#        are read from ENTROPY_DIR/../.github/workflows)
#        scripts/check-version.sh --selftest      (each site changed or removed in a copy must fail)
# Exit 0 clean, 1 offenders, 2 error. Needs python3.
set -u

if [ "${1:-}" = "--selftest" ]; then
    mode=selftest
    root=$(cd "$(dirname "$0")/.." && pwd) || exit 2
else
    mode=check
    root=${1:-.}
fi
[ -f "$root/Cargo.toml" ] || { echo "check-version: no Cargo.toml in $root" >&2; exit 2; }

exec python3 -I - "$mode" "$root" <<'PY'
import re, shutil, sys, tempfile
from pathlib import Path

MEMBERS = ["core", "ffi", "ffi/guard", "ffi/jni", "ffi/capi", "pi/app", "pi/sim"]
V = r"([0-9]+\.[0-9]+\.[0-9]+)"
# (path from Entropy/, regex whose one group is the version, how many times it must appear)
SITES = [
    ("mobile/android/app/build.gradle.kts", r'^\s*versionName = "' + V + r'"$', 1),
    ("mobile/android/capture-control/build.gradle.kts", r'^\s*versionName = "' + V + r'"$', 1),
    ("mobile/android/expected/manifest-shipping.txt", r"^versionName " + V + r"$", 1),
    ("mobile/android/expected/manifest-withTestRegistry.txt", r"^versionName " + V + r"$", 1),
    # The --selftest-apk stand-ins for aapt2's output on the shipping APK, checked against the expected manifest.
    ("scripts/testdata/apk/badging.txt", r"^package: name='com\.keepcrypt\.entropy' versionCode='1' versionName='" + V + r"'", 1),
    ("scripts/testdata/apk/xmltree.txt", r'versionName\(0x0101021c\)="' + V + r'" \(Raw: "[0-9.]+"\)$', 1),
    ("scripts/testdata/apk/xmltree.txt", r'versionName\(0x0101021c\)="[0-9.]+" \(Raw: "' + V + r'"\)$', 1),
    ("mobile/android/screens/src/commonMain/kotlin/com/keepcrypt/entropy/screens/HomeScreens.kt",
     r'^const val APP_VERSION = "' + V + r'"$', 1),
    ("mobile/ios/KeepCrypt/Info.plist", r"<key>CFBundleShortVersionString</key>\s*<string>" + V + r"</string>", 1),
    ("mobile/ios/expected/Shipping-Info.json", r'"CFBundleShortVersionString": "' + V + r'"', 1),
    ("mobile/ios/expected/WithTestRegistry-Info.json", r'"CFBundleShortVersionString": "' + V + r'"', 1),
    ("mobile/ios/KeepCrypt/Texts.swift", r'^let appVersion = "' + V + r'"$', 1),
    ("mobile/ios/KeepCryptTests/CeremonyCheckBackupTests.swift", r'"Version ' + V + r'"', 1),
    ("mobile/ios/KeepCryptTests/ScreenTextsTests.swift", r'"' + V + r' development build: do not use for real funds\."', 1),
    ("mobile/ios/KeepCryptUITests/MixedJourneyUITests.swift", r'"Version ' + V + r'"', 1),
    ("mobile/ios/KeepCryptUITests/SnapshotJourneyUITests.swift", r'"Version ' + V + r'"', 1),
    ("pi/os/package/keepcrypt-pi/keepcrypt-pi.mk", r"^KEEPCRYPT_PI_VERSION = " + V + r"$", 1),
    ("pi/os/Makefile", r"^IMAGE := keepcrypt-pi-" + V + r"-st7789-240x240\.img$", 1),
    ("pi/os/Makefile", r"^BUILT_BIN := \$\(OUT\)/build/keepcrypt-pi-" + V + r"/target/", 1),
    ("pi/os/board/pizero/genimage.cfg", r"^image keepcrypt-pi-" + V + r"-st7789-240x240\.img \{$", 1),
    ("../.github/workflows/entropy-pi-image.yml", r"/build/keepcrypt-pi-" + V + r"/target/", 1),
    ("../.github/workflows/entropy-pi-image.yml", r"\(keepcrypt-pi-" + V + r"-st7789-240x240\.img,", 1),
    ("CLAUDE.md", r"images/keepcrypt-pi-" + V + r"-st7789-240x240\.img", 1),
    ("CLAUDE.md", r"/build/keepcrypt-pi-" + V + r"/target/", 1),
]


def workspace_version(root):
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    section = re.search(r"^\[workspace\.package\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not section:
        return None, "Cargo.toml: no [workspace.package]"
    found = re.findall(r'^version = "' + V + r'"$', section.group(1), re.M)
    if len(found) != 1:
        return None, "Cargo.toml: [workspace.package] names %d versions, not 1" % len(found)
    return found[0], None


def check(root):
    version, error = workspace_version(root)
    if error:
        return [error]
    problems = []
    for member in MEMBERS:
        path = root / member / "Cargo.toml"
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if len(re.findall(r"^version\.workspace = true$", text, re.M)) != 1 or re.search(r'^version = "', text, re.M):
            problems.append("%s/Cargo.toml: does not take the workspace version (version.workspace = true)" % member)
    for rel, pattern, count in SITES:
        path = root / rel
        if not path.is_file():
            problems.append("%s: missing" % rel)
            continue
        text = path.read_text(encoding="utf-8")
        hits = list(re.finditer(pattern, text, re.M))
        if len(hits) != count:
            problems.append("%s: %d matches of %s, wanted %d" % (rel, len(hits), pattern, count))
        for hit in hits:
            if hit.group(1) != version:
                line = text.count("\n", 0, hit.start()) + 1
                problems.append("%s:%d: names %s, the workspace is %s" % (rel, line, hit.group(1), version))
    return problems


def selftest(root):
    files = ["Cargo.toml"] + [m + "/Cargo.toml" for m in MEMBERS] + sorted({rel for rel, _, _ in SITES})
    passed = failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "Entropy"

        def fresh():
            if base.parent.exists():
                shutil.rmtree(base.parent)
            for rel in files:
                (base / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / rel, base / rel)

        def case(label, change, want_clean, want_text=""):
            nonlocal passed, failed
            fresh()
            change()
            problems = check(base)
            ok = (not problems) if want_clean else (bool(problems) and all(want_text in p for p in problems))
            if ok:
                passed += 1
            else:
                failed += 1
                print("FAIL %s: %s" % (label, problems or "clean"))

        def edit(rel, pattern, replace):
            def change():
                path = base / rel
                text = path.read_text(encoding="utf-8")
                hit = re.search(pattern, text, re.M)
                if not hit:
                    raise SystemExit("selftest: %s holds no %s" % (rel, pattern))
                path.write_text(text[:hit.start(1)] + replace(hit) + text[hit.end(1):], encoding="utf-8")
            return change

        case("the tree as it is", lambda: None, True)
        for n, (rel, pattern, _) in enumerate(SITES):
            case("site %d (%s) names another version" % (n, rel), edit(rel, pattern, lambda h: "9.9.9"), False, rel)
            case("site %d (%s) removed" % (n, rel), edit(rel, pattern, lambda h: "9.9"), False, rel)
        version, _ = workspace_version(root)
        case("the workspace alone moves", edit("Cargo.toml", r'^version = "' + V + r'"$', lambda h: "9.9.9"), False)
        case("a crate pins its own version",
             edit("ffi/capi/Cargo.toml", r"^(version\.workspace = true)$", lambda h: 'version = "%s"' % version),
             False, "ffi/capi/Cargo.toml")
        print("check-version selftest: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


mode, root = sys.argv[1], Path(sys.argv[2])
try:
    if mode == "selftest":
        sys.exit(selftest(root))
    problems = check(root)
except OSError as error:
    print("check-version: %s" % error, file=sys.stderr)
    sys.exit(2)
for problem in problems:
    print("check-version: %s" % problem)
if problems:
    sys.exit(1)
print("check-version: every site names %s" % workspace_version(root)[0])
PY
