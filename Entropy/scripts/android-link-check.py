#!/usr/bin/env python3
"""The instrumented-test APKs link against the shrunk app (tasks/todo.md, M7 D2b).

A test APK leaves out every library the app also carries and uses the app's copy at run time, so
when R8 shrinks the app, a class or method only the tests use is gone and the test runner fails on
the emulator (NoClassDefFoundError: kotlin.LazyKt, the first local run with R8). This reads both
APKs' dex files through dexdump and fails on any class the test APK names that neither APK
defines, and any method it calls on an app class that the class and its supertypes do not
define. Platform classes (java, javax, android, dalvik, org.json, org.xml, org.xmlpull, org.w3c,
sun, libcore) are the device's and are not judged; a method reached through
java.lang.Object must be one of Object's own.

Usage:
  python3 -I scripts/android-link-check.py check APP_APK TEST_APK DEXDUMP
    Prints the counts and every missing class and method; fails on any.
  python3 -I scripts/android-link-check.py --selftest
    Runs check on APKs whose "dex" entries hold dexdump's text, read by a stand-in dexdump.

Prints "FAIL: link-check: ..." on stderr for a check that fails.
Exit: 0 passed; 1 a check failed; 2 bad usage.
"""

import os
import re
import subprocess
import sys
import tempfile
import zipfile


class Fail(Exception):
    pass


PLATFORM = re.compile(r"L(java|javax|android|dalvik|org/json|org/xml|org/xmlpull|org/w3c|sun|libcore)/")
CLASS = re.compile(r"\s*Class descriptor\s*:\s*'(.*)'")
SUPER = re.compile(r"\s*Superclass\s*:\s*'(.*)'")
IFACE = re.compile(r"\s*#\d+\s*:\s*'(L.*;)'")
NAME = re.compile(r"\s*name\s*:\s*'(.*)'")
TYPE = re.compile(r"\s*type\s*:\s*'(\(.*)'")
# A dex method name may hold "-": Kotlin's names for functions taking or giving an inline value class
# (getPositionInWindow-F1C5BW0); the first CALL here skipped them, and run 45016186578 found one shrunk.
CALL = re.compile(r"(L[\w/$-]+;)\.([^\s:(]+):(\([^ ]*)\s")
# Every instruction calling a method names it so; one CALL cannot read fails the check, never skipped.
INVOKE = re.compile(r"\binvoke-[\w/-]+ .*// method@")
REF = re.compile(r"L[\w/$-]+;")
# What every class inherits from java.lang.Object; any other platform supertype is taken to define
# what is called (its methods are the device's, not in either APK).
OBJECT_METHODS = {"<init>", "equals", "hashCode", "toString", "getClass", "notify", "notifyAll", "wait", "clone", "finalize"}


def dump(apk, dexdump, work):
    out = []
    with zipfile.ZipFile(apk) as z:
        dexes = sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
        if not dexes:
            raise Fail(f"{apk} holds no classes.dex")
        for n in dexes:
            path = os.path.join(work, os.path.basename(apk) + "." + n)
            with open(path, "wb") as f:
                f.write(z.read(n))
            r = subprocess.run([dexdump, "-d", path], capture_output=True, text=True)
            if r.returncode != 0:
                raise Fail(f"dexdump failed on {apk}:{n}")
            out.append(r.stdout)
    return "".join(out)


def parse(text):
    methods, supers, cls, name = {}, {}, None, None
    for line in text.splitlines():
        m = CLASS.match(line)
        if m:
            cls = m.group(1)
            methods.setdefault(cls, set())
            supers.setdefault(cls, [])
            continue
        if cls is None:
            continue
        m = SUPER.match(line) or IFACE.match(line)
        if m:
            supers[cls].append(m.group(1))
            continue
        m = NAME.match(line)
        if m:
            name = m.group(1)
            continue
        m = TYPE.match(line)
        if m and name is not None:
            methods[cls].add(f"{name}:{m.group(1)}")
    return methods, supers


def check(app_apk, test_apk, dexdump):
    with tempfile.TemporaryDirectory() as work:
        app_text = dump(app_apk, dexdump, work)
        test_text = dump(test_apk, dexdump, work)
    app_methods, app_supers = parse(app_text)
    test_methods, test_supers = parse(test_text)
    methods = {**app_methods, **test_methods}
    supers = {**app_supers, **test_supers}

    def defines(cls, sig, seen):
        if cls in seen:
            return False
        seen.add(cls)
        if cls == "Ljava/lang/Object;":
            return sig.split(":")[0] in OBJECT_METHODS
        if PLATFORM.match(cls):
            return True
        if cls not in methods:
            return False
        return sig in methods[cls] or any(defines(s, sig, seen) for s in supers.get(cls, []))

    unread = sorted({line.strip() for line in test_text.splitlines() if INVOKE.search(line) and not CALL.search(line)})
    if unread:
        for x in unread[:20]:
            print(f"  unread: {x}")
        raise Fail(f"{len(unread)} method calls in {test_apk} are not in the form this check reads (above)")
    classes = sorted({c for c in REF.findall(test_text) if not PLATFORM.match(c) and c not in methods})
    calls = sorted({
        f"{c}.{n}:{s}" for c, n, s in CALL.findall(test_text)
        if c in app_methods and c not in test_methods and not defines(c, f"{n}:{s}", set())
    })
    print(f"link-check: {os.path.basename(test_apk)} against {os.path.basename(app_apk)}: "
          f"{len(classes)} missing classes, {len(calls)} missing methods")
    for x in classes + calls:
        print(f"  missing: {x}")
    if classes or calls:
        raise Fail(f"{test_apk} names what {app_apk} no longer defines (above)")


STUB = """#!/bin/sh
[ "$1" = -d ] || exit 2
cat "$2"
"""


def selftest():
    failures = 0

    def cls(name, sup="Ljava/lang/Object;", methods=(), ifaces=(), code=""):
        lines = [f"  Class descriptor  : '{name}'", f"  Superclass        : '{sup}'", "  Interfaces        -"]
        lines += [f"    #{i}              : '{x}'" for i, x in enumerate(ifaces)]
        for n, t in methods:
            lines += [f"      name          : '{n}'", f"      type          : '{t}'"]
        lines.append(code)
        return "\n".join(lines) + "\n"

    app = (cls("Lkotlin/LazyKt__LazyJVMKt;", methods=[("lazy", "(Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;")])
           + cls("Lkotlin/LazyKt;", sup="Lkotlin/LazyKt__LazyJVMKt;")
           + cls("Lkotlin/Lazy;", methods=[("getValue", "()Ljava/lang/Object;")])
           + cls("Lcom/keepcrypt/entropy/ffi/Core;", methods=[("selfTest", "()Lcom/keepcrypt/entropy/ffi/Reply;")])
           + cls("Lcom/keepcrypt/entropy/ffi/Reply;")
           + cls("Lkotlin/jvm/functions/Function0;"))
    call_lazy = "|0000: invoke-static {v0}, Lkotlin/LazyKt;.lazy:(Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy; // method@1\n"
    call_core = "|0002: invoke-static {}, Lcom/keepcrypt/entropy/ffi/Core;.selfTest:()Lcom/keepcrypt/entropy/ffi/Reply; // method@2\n"
    call_list = "|0004: invoke-interface {v1}, Ljava/util/List;.size:()I // method@3\n"
    test_ok = cls("Lcom/keepcrypt/entropy/FlowTest;", code=call_lazy + call_core + call_list)
    with tempfile.TemporaryDirectory() as d:
        stub = os.path.join(d, "dexdump")
        with open(stub, "w") as f:
            f.write(STUB)
        os.chmod(stub, 0o755)

        def apk(name, text, entry="classes.dex"):
            path = os.path.join(d, name)
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(entry, text)
            return path

        def case(label, app_text, test_text, want_fail, entry="classes.dex"):
            nonlocal failures
            try:
                check(apk("app.apk", app_text, entry), apk("test.apk", test_text), stub)
                got = False
            except Fail:
                got = True
            ok = got == want_fail
            print(f"{'ok' if ok else 'BAD'}: {label}")
            if not ok:
                failures += 1

        case("every class and method resolves, one inherited from a facade's part, one a platform interface's", app, test_ok, False)
        case("a class neither APK defines fails", app.replace("Lkotlin/LazyKt;", "Lkotlin/Gone;"), test_ok, True)
        case("a method shrunk from a kept class fails",
             app.replace("'selfTest'", "'other'"), test_ok, True)
        case("a method found on no supertype fails",
             app.replace("Superclass        : 'Lkotlin/LazyKt__LazyJVMKt;'", "Superclass        : 'Ljava/lang/Object;'"), test_ok, True)
        case("a class the test APK defines itself passes",
             app, test_ok + cls("Lkotlinx/Helper;") + "|0006: invoke-static {}, Lkotlinx/Helper;.run:()V // method@4\n", False)
        case("a method found through an interface passes",
             app.replace("Lkotlin/LazyKt;'\n  Superclass        : 'Lkotlin/LazyKt__LazyJVMKt;'\n  Interfaces        -",
                         "Lkotlin/LazyKt;'\n  Superclass        : 'Ljava/lang/Object;'\n  Interfaces        -\n    #0              : 'Lkotlin/LazyKt__LazyJVMKt;'"),
             test_ok, False)
        case("an APK with no classes.dex fails", app, test_ok, True, entry="other.txt")
        mangled = cls("Landroidx/compose/ui/semantics/SemanticsNode;", methods=[("getPositionInWindow-F1C5BW0", "()J")])
        call_mangled = "|0008: invoke-virtual {v2}, Landroidx/compose/ui/semantics/SemanticsNode;.getPositionInWindow-F1C5BW0:()J // method@5\n"
        case("a mangled name (an inline value class's) the app keeps passes",
             app + mangled, test_ok + cls("Lcom/keepcrypt/entropy/Pos;", code=call_mangled), False)
        case("a mangled name the app shrank fails",
             app + mangled.replace("getPositionInWindow-F1C5BW0", "getId"), test_ok + cls("Lcom/keepcrypt/entropy/Pos;", code=call_mangled), True)
        case("a method call in a form the check cannot read fails",
             app, test_ok + cls("Lcom/keepcrypt/entropy/Odd;", code="|000a: invoke-virtual {v0}, Lcom/x/Y;.a b:()V // method@6\n"), True)
    print(f"android-link-check selftest: {'all cases behave' if failures == 0 else f'{failures} cases misbehave'}")
    return 0 if failures == 0 else 1


def main(argv):
    try:
        if argv == ["--selftest"]:
            return selftest()
        if len(argv) == 4 and argv[0] == "check":
            check(*argv[1:])
            return 0
    except Fail as e:
        print(f"FAIL: link-check: {e}", file=sys.stderr)
        return 1
    print("usage: python3 -I scripts/android-link-check.py check APP_APK TEST_APK DEXDUMP | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
