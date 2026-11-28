#!/usr/bin/env python3
"""The emulator and system images of the Android workflow's leg jobs, pinned (tasks/todo.md, M7 D4).

sdkmanager installs whatever revision Google's repository offers that day. The legs install the
revisions in mobile/android/expected/emulator-pins.txt instead, each zip by its URL and checked by
size, SHA-1 (the value Google's repository index publishes) and SHA-256 before anything is
unpacked. A zip holds one top directory, which is unpacked to its place under SDK_ROOT; any entry
outside it, an absolute name or a ".." component fails. Each unpacked package's source.properties
must then name the pinned revision.

Usage:
  python3 -I scripts/android-sdk-install.py install SDK_ROOT PINS [CACHE]
    Every package of PINS into SDK_ROOT (an absolute path; a package's place must not exist yet).
    With CACHE (an absolute path), each zip is taken from CACHE when it is there and downloaded into
    it when not; a cached zip is checked exactly as a downloaded one, every run, and one that fails
    is removed. Prints each package's name, revision, size and SHA-256.
  python3 -I scripts/android-sdk-install.py --selftest
    Runs install on zips it writes and serves as file:// URLs in a temporary directory.

PINS: one package per line, fields split by whitespace, "#" lines and blank lines ignored:
  path revision url size sha1 sha256 place top
where place is the directory under SDK_ROOT the zip's top directory becomes (for the emulator,
"emulator"; for an image, system-images/android-34/default/x86_64), and top is that directory's name
in the zip.

Needs curl and unzip. Prints "FAIL: sdk-install: ..." on stderr for a check that fails.
Exit: 0 passed; 1 a check failed; 2 bad usage.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


class Fail(Exception):
    pass


FIELDS = ("path", "revision", "url", "size", "sha1", "sha256", "place", "top")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._;-]*")
PLACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*")


def read_pins(path):
    pins = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != len(FIELDS):
                raise Fail(f"{path}:{n}: {len(parts)} fields, not {len(FIELDS)}")
            p = dict(zip(FIELDS, parts))
            if not NAME.fullmatch(p["path"]) or not re.fullmatch(r"[0-9]+(\.[0-9]+)*", p["revision"]):
                raise Fail(f"{path}:{n}: bad package path or revision")
            if not re.fullmatch(r"(https://dl\.google\.com/android/repository/|file:///)[A-Za-z0-9._/-]+\.zip", p["url"]):
                raise Fail(f"{path}:{n}: the URL is not a zip on dl.google.com/android/repository")
            if not p["size"].isdigit() or not re.fullmatch(r"[0-9a-f]{40}", p["sha1"]) or not re.fullmatch(r"[0-9a-f]{64}", p["sha256"]):
                raise Fail(f"{path}:{n}: bad size, SHA-1 or SHA-256")
            if not PLACE.fullmatch(p["place"]) or ".." in p["place"].split("/") or not NAME.fullmatch(p["top"]) or p["top"] == "..":
                raise Fail(f"{path}:{n}: bad place or top directory")
            pins.append(p)
    if not pins:
        raise Fail(f"{path} pins nothing")
    if len({p["path"] for p in pins}) != len(pins) or len({p["place"] for p in pins}) != len(pins):
        raise Fail(f"{path} names a package or a place twice")
    return pins


def hashes(path):
    a, b, n = hashlib.sha1(), hashlib.sha256(), 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            a.update(block)
            b.update(block)
            n += len(block)
    return n, a.hexdigest(), b.hexdigest()


def check_entries(zpath, top):
    with zipfile.ZipFile(zpath) as z:
        names = z.namelist()
    if not names:
        raise Fail(f"{zpath} is empty")
    for name in names:
        parts = name.split("/")
        if name.startswith("/") or "\\" in name or ".." in parts or parts[0] != top:
            raise Fail(f"{zpath} holds {name!r}, outside {top}/")


def install(sdk, pins_path, cache=None):
    if not os.path.isabs(sdk):
        raise Fail(f"SDK_ROOT must be an absolute path: {sdk}")
    if cache is not None and not os.path.isabs(cache):
        raise Fail(f"CACHE must be an absolute path: {cache}")
    pins = read_pins(pins_path)
    os.makedirs(sdk, exist_ok=True)
    work = tempfile.mkdtemp(prefix="kc-sdk-install.", dir=sdk)
    try:
        for p in pins:
            dest = os.path.join(sdk, p["place"])
            if os.path.lexists(dest):
                raise Fail(f"{dest} exists already")
            if cache is None:
                z = os.path.join(work, "package.zip")
            else:
                os.makedirs(cache, exist_ok=True)
                z = os.path.join(cache, p["url"].rsplit("/", 1)[1])
            source = "the cache" if os.path.isfile(z) else "downloaded"
            if source == "downloaded":
                part = os.path.join(work, "download.part")
                r = subprocess.run(["curl", "-fsSL", "--retry", "5", "--proto", "=https,file", "-o", part, p["url"]])
                if r.returncode != 0:
                    raise Fail(f"curl could not fetch {p['url']}")
                os.replace(part, z)
            size, sha1, sha256 = hashes(z)
            if (size, sha1, sha256) != (int(p["size"]), p["sha1"], p["sha256"]):
                os.remove(z)
                raise Fail(f"{p['url']} ({source}): {size} bytes, SHA-1 {sha1}, SHA-256 {sha256}, not the pin's")
            check_entries(z, p["top"])
            out = os.path.join(work, "out")
            r = subprocess.run(["unzip", "-q", z, "-d", out])
            if r.returncode != 0:
                raise Fail(f"unzip failed on {p['url']}")
            props = os.path.join(out, p["top"], "source.properties")
            try:
                with open(props, encoding="utf-8") as f:
                    revs = [l.split("=", 1)[1].strip() for l in f if l.startswith("Pkg.Revision=")]
            except OSError:
                raise Fail(f"{p['path']} has no source.properties") from None
            if revs != [p["revision"]]:
                raise Fail(f"{p['path']}'s source.properties gives revision {revs}, not {p['revision']}")
            os.makedirs(os.path.dirname(dest) or sdk, exist_ok=True)
            os.rename(os.path.join(out, p["top"]), dest)
            shutil.rmtree(out)
            if cache is None:
                os.remove(z)
            print(f"{p['path']} {p['revision']} ({source}): {size} bytes, SHA-256 {sha256}, in {p['place']}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def selftest():
    failures = 0

    def case(label, fn, want_fail):
        nonlocal failures
        try:
            fn()
            got = False
        except Fail as e:
            got = True
            detail = str(e)
        ok = got == want_fail
        print(f"{'ok' if ok else 'BAD'}: {label}" + (f" ({detail})" if got and not ok else ""))
        if not ok:
            failures += 1

    with tempfile.TemporaryDirectory() as d:
        def make_zip(name, entries):
            path = os.path.join(d, name)
            with zipfile.ZipFile(path, "w") as z:
                for n, data in entries.items():
                    z.writestr(n, data)
            return path

        emu = make_zip("emu.zip", {"emulator/source.properties": "Pkg.Revision=37.3.10\n", "emulator/emulator": "#!/bin/sh\n"})
        img = make_zip("img.zip", {"x86_64/source.properties": "Pkg.Desc=x\nPkg.Revision=4\n", "x86_64/system.img": "s"})

        def line(path, rev, z, place, top, size=None, sha1=None, sha256=None):
            n, a, b = hashes(z)
            return " ".join([path, rev, "file://" + z, str(size if size is not None else n), sha1 or a, sha256 or b, place, top])

        good = [line("emulator", "37.3.10", emu, "emulator", "emulator"),
                line("system-images;android-34;default;x86_64", "4", img, "system-images/android-34/default/x86_64", "x86_64")]

        def pins(lines):
            p = os.path.join(d, "pins.txt")
            with open(p, "w") as f:
                f.write("# test pins\n\n" + "\n".join(lines) + "\n")
            return p

        counter = [0]

        def run(lines):
            counter[0] += 1
            sdk = os.path.join(d, f"sdk{counter[0]}")
            install(sdk, pins(lines))
            return sdk

        def good_run():
            sdk = run(good)
            if not os.path.isfile(os.path.join(sdk, "emulator", "emulator")):
                raise Fail("the emulator was not unpacked")
            if not os.path.isfile(os.path.join(sdk, "system-images/android-34/default/x86_64/system.img")):
                raise Fail("the image was not unpacked")
            if [e for e in os.listdir(sdk) if e.startswith("kc-sdk-install.")]:
                raise Fail("the work directory was left behind")

        case("the pinned packages install", good_run, False)
        case("another size fails", lambda: run([line("emulator", "37.3.10", emu, "emulator", "emulator", size=1)]), True)
        case("another SHA-1 fails", lambda: run([line("emulator", "37.3.10", emu, "emulator", "emulator", sha1="0" * 40)]), True)
        case("another SHA-256 fails", lambda: run([line("emulator", "37.3.10", emu, "emulator", "emulator", sha256="0" * 64)]), True)
        case("another revision in source.properties fails", lambda: run([line("emulator", "37.4.1", emu, "emulator", "emulator")]), True)
        case("another top directory fails", lambda: run([line("emulator", "37.3.10", emu, "emulator", "x86_64")]), True)
        trav = make_zip("trav.zip", {"emulator/source.properties": "Pkg.Revision=1\n", "emulator/../evil": "x"})
        case("a '..' entry fails", lambda: run([line("emulator", "1", trav, "emulator", "emulator")]), True)
        out = make_zip("out.zip", {"emulator/source.properties": "Pkg.Revision=1\n", "other/file": "x"})
        case("an entry outside the top directory fails", lambda: run([line("emulator", "1", out, "emulator", "emulator")]), True)
        noprops = make_zip("noprops.zip", {"emulator/emulator": "x"})
        case("no source.properties fails", lambda: run([line("emulator", "1", noprops, "emulator", "emulator")]), True)
        case("a missing zip fails", lambda: run([good[0].replace("emu.zip", "none.zip")]), True)
        case("an http URL fails", lambda: run([good[0].replace("file://", "http://x")]), True)
        case("another host fails", lambda: run([good[0].replace("file://" + d, "https://example.com/android/repository")]), True)
        case("a place with '..' fails", lambda: run([good[0].replace(" emulator emulator", " ../emulator emulator")]), True)
        case("an absolute place fails", lambda: run([good[0].replace(" emulator emulator", " /emulator emulator")]), True)
        case("a package twice fails", lambda: run([good[0], good[0]]), True)
        case("seven fields fail", lambda: run([good[0].rsplit(" ", 1)[0]]), True)
        case("no pins fail", lambda: run([]), True)

        def exists_run():
            sdk = os.path.join(d, "sdk-exists")
            os.makedirs(os.path.join(sdk, "emulator"))
            install(sdk, pins(good))

        case("a place that exists already fails", exists_run, True)
        case("a relative SDK_ROOT fails", lambda: install("relative/sdk", pins(good)), True)
        cache = os.path.join(d, "cache")

        def cached_runs():
            for i in (1, 2):
                sdk = os.path.join(d, f"sdk-cached{i}")
                install(sdk, pins(good), cache)
                if not os.path.isfile(os.path.join(sdk, "emulator", "emulator")):
                    raise Fail("the emulator was not unpacked")
            if sorted(os.listdir(cache)) != ["emu.zip", "img.zip"]:
                raise Fail(f"the cache holds {sorted(os.listdir(cache))}")

        case("a run fills the cache and a second runs from it", cached_runs, False)

        def tampered():
            with open(os.path.join(cache, "emu.zip"), "ab") as f:
                f.write(b"x")
            try:
                install(os.path.join(d, "sdk-tampered"), pins(good), cache)
            finally:
                if os.path.exists(os.path.join(cache, "emu.zip")):
                    raise Fail("the changed zip was left in the cache")

        case("a changed zip in the cache fails and is removed", tampered, True)
        case("after that the next run downloads it again",
             lambda: install(os.path.join(d, "sdk-again"), pins(good), cache), False)
        case("a relative CACHE fails", lambda: install(os.path.join(d, "sdk-rel"), pins(good), "rel/cache"), True)
    print(f"android-sdk-install selftest: {'all cases behave' if failures == 0 else f'{failures} cases misbehave'}")
    return 0 if failures == 0 else 1


def main(argv):
    try:
        if argv == ["--selftest"]:
            return selftest()
        if len(argv) in (3, 4) and argv[0] == "install":
            install(*argv[1:])
            return 0
    except Fail as e:
        print(f"FAIL: sdk-install: {e}", file=sys.stderr)
        return 1
    print("usage: python3 -I scripts/android-sdk-install.py install SDK_ROOT PINS [CACHE] | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
