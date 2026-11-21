#!/usr/bin/env python3
"""The Android workflow's two clean builds of the unsigned shipping APK (tasks/todo.md, M7 D1).

The build job and job build-b each build app-shipping-release-unsigned.apk from one commit, on two
fresh runners, at two checkout paths, in two time zones and under two umasks; job
apk-reproducible requires the same bytes. Each side prints the APK's SHA-256 and the SHA-256 of
every entry in it, so a difference names the entries that differ without either APK leaving its
job.

Usage:
  python3 -I scripts/android-repro.py sums APK
    Prints "<sha256>  apk" for the APK's bytes, then one "<sha256>  <entry>" line per zip entry, in
    the APK's own order (the order is part of the bytes), each entry's name, size and CRC checked by
    reading it whole. An APK that is no zip, holds no entry, names an entry twice, or holds no
    lib/<abi>/libkeepcrypt.so for each of MA:23's three ABIs fails.
  python3 -I scripts/android-repro.py compare
    KC_A and KC_B hold the two jobs' sums as their outputs gave them (one newline at the end is
    dropped). Each must be well formed (the apk line first, then entries); they must be equal line
    for line. On a difference it prints each line only one side has, then fails.
  python3 -I scripts/android-repro.py --selftest
    Runs both forms on zips it writes in a temporary directory.

Prints "FAIL: android-repro: ..." on stderr for a check that fails.
Exit: 0 passed; 1 a check failed; 2 bad usage.
"""

import hashlib
import os
import re
import sys
import tempfile
import zipfile

ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
LINE = re.compile(r"[0-9a-f]{64}  (apk|[^\n]+)")


class Fail(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sums(apk):
    if not os.path.isfile(apk):
        raise Fail(f"no APK at {apk}")
    try:
        with zipfile.ZipFile(apk) as z:
            infos = z.infolist()
            lines = [f"{sha256_file(apk)}  apk"]
            seen = set()
            for info in infos:
                name = info.filename
                if name in seen:
                    raise Fail(f"{apk} names {name} twice")
                if "\n" in name or name == "apk":
                    raise Fail(f"{apk} has an entry named {name!r}")
                seen.add(name)
                h = hashlib.sha256()
                with z.open(info) as e:
                    for block in iter(lambda: e.read(1 << 20), b""):
                        h.update(block)
                lines.append(f"{h.hexdigest()}  {name}")
    except zipfile.BadZipFile as e:
        raise Fail(f"{apk} is no zip: {e}") from None
    if len(lines) == 1:
        raise Fail(f"{apk} holds no entry")
    for abi in ABIS:
        if f"lib/{abi}/libkeepcrypt.so" not in seen:
            raise Fail(f"{apk} holds no lib/{abi}/libkeepcrypt.so")
    return lines


def parse(name, text):
    if text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise Fail(f"{name} is empty")
    lines = text.split("\n")
    for i, line in enumerate(lines):
        m = LINE.fullmatch(line)
        if not m:
            raise Fail(f"{name} line {i + 1} is not '<sha256>  <name>': {line!r}")
        if (m.group(1) == "apk") != (i == 0):
            raise Fail(f"{name}: the apk line must be the first and only the first")
    if len(lines) < 2:
        raise Fail(f"{name} lists no entry")
    return lines


def compare(a_text, b_text):
    a = parse("KC_A", a_text)
    b = parse("KC_B", b_text)
    print(f"a: {a[0]}, {len(a) - 1} entries")
    print(f"b: {b[0]}, {len(b) - 1} entries")
    if a == b:
        print("PASS: the two clean builds gave one unsigned APK")
        return
    sa, sb = set(a), set(b)
    for line in a:
        if line not in sb:
            print(f"only a: {line}")
    for line in b:
        if line not in sa:
            print(f"only b: {line}")
    if sa == sb:
        print("(the same lines in another order)")
    raise Fail("the two clean builds differ")


def write_apk(path, entries, order=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for name in order or entries:
            z.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), entries[name])


def selftest():
    failures = 0

    def case(label, fn, want_fail):
        nonlocal failures
        try:
            fn()
            got = False
        except Fail:
            got = True
        ok = got == want_fail
        print(f"{'ok' if ok else 'BAD'}: {label}")
        if not ok:
            failures += 1

    base = {f"lib/{abi}/libkeepcrypt.so": abi.encode() for abi in ABIS}
    base["classes.dex"] = b"dex\n035\0"
    base["AndroidManifest.xml"] = b"\3\0\10\0"
    with tempfile.TemporaryDirectory() as d:
        a = os.path.join(d, "a.apk")
        write_apk(a, base)
        b = os.path.join(d, "b.apk")
        write_apk(b, base)
        sa = "\n".join(sums(a)) + "\n"
        sb = "\n".join(sums(b))
        case("sums of a well-formed APK", lambda: sums(a), False)
        case("one APK built twice compares equal", lambda: compare(sa, sb), False)
        changed = dict(base)
        changed["classes.dex"] = b"dex\n036\0"
        c = os.path.join(d, "c.apk")
        write_apk(c, changed)
        case("a changed entry differs", lambda: compare(sa, "\n".join(sums(c))), True)
        r = os.path.join(d, "r.apk")
        write_apk(r, base, order=list(reversed(list(base))))
        case("the same entries in another order differ", lambda: compare(sa, "\n".join(sums(r))), True)
        more = dict(base)
        more["META-INF/extra"] = b"x"
        m = os.path.join(d, "m.apk")
        write_apk(m, more)
        case("an entry more differs", lambda: compare(sa, "\n".join(sums(m))), True)
        t = os.path.join(d, "t.apk")
        with zipfile.ZipFile(t, "w") as z:
            for name, data in base.items():
                z.writestr(zipfile.ZipInfo(name, (2026, 11, 22, 4, 0, 0)), data)
        case("other timestamps (same entries) differ by the APK's hash", lambda: compare(sa, "\n".join(sums(t))), True)
        for abi in ABIS:
            no = {k: v for k, v in base.items() if k != f"lib/{abi}/libkeepcrypt.so"}
            p = os.path.join(d, f"no-{abi}.apk")
            write_apk(p, no)
            case(f"no libkeepcrypt.so for {abi} fails", lambda p=p: sums(p), True)
        junk = os.path.join(d, "junk.apk")
        with open(junk, "wb") as f:
            f.write(b"not a zip")
        case("a file that is no zip fails", lambda: sums(junk), True)
        case("a missing APK fails", lambda: sums(os.path.join(d, "none.apk")), True)
        empty = os.path.join(d, "empty.apk")
        write_apk(empty, {})
        case("an APK with no entry fails", lambda: sums(empty), True)
        twice = os.path.join(d, "twice.apk")
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            write_apk(twice, base, order=list(base) + ["classes.dex"])
        case("an entry named twice fails", lambda: sums(twice), True)
        lines = sa.rstrip("\n").split("\n")
        case("empty output fails", lambda: compare("", sb), True)
        case("an apk line alone fails", lambda: compare(lines[0], lines[0]), True)
        case("no apk line first fails", lambda: compare("\n".join(lines[1:] + lines[:1]), sb), True)
        case("a second apk line fails", lambda: compare(sa + lines[0], sb), True)
        case("upper-case hex fails", lambda: compare(sa.upper(), sb), True)
        case("an empty line fails", lambda: compare(sa + "\n", sb), True)
        case("a short hash fails", lambda: compare(sa[1:], sb), True)
    print(f"android-repro selftest: {'all cases behave' if failures == 0 else f'{failures} cases misbehave'}")
    return 0 if failures == 0 else 1


def main(argv):
    try:
        if argv == ["--selftest"]:
            return selftest()
        if len(argv) == 2 and argv[0] == "sums":
            print("\n".join(sums(argv[1])))
            return 0
        if argv == ["compare"]:
            for v in ("KC_A", "KC_B"):
                if v not in os.environ:
                    raise Fail(f"{v} is not set")
            compare(os.environ["KC_A"], os.environ["KC_B"])
            return 0
    except Fail as e:
        print(f"FAIL: android-repro: {e}", file=sys.stderr)
        return 1
    print("usage:" + __doc__.split("Usage:")[1].split('Prints "FAIL')[0].rstrip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
