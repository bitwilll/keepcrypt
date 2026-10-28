#!/usr/bin/env python3
"""The CI age -d hand-off for the Android app's backup (tasks/todo.md, M5 group 18, its second item).

Python 3.9+, standard library only. scripts/android-instrument.sh pipes the raw output of one
`am instrument -r` run of the backup's emulator test straight into this script (its age: form). That test
saves the CI throwaway seed's backup to the emulator's Downloads through the system's picker, and reports
three instrumentation status values (status code 2): the backup passphrase, read from the in-process
Secret, under the key kc_ci_throwaway_passphrase, the one place it leaves the test's process; the file's
name, core's suggested one; and the wallet summary's fingerprint. The gate's KtTestChannel rule allows that
key only under mobile/android/app/src/androidTest/ and in this file.

  scripts/android-age-check.py --raw RAW ADB SERIAL [--age AGE]
      Reads the whole run from stdin. Writes it to RAW (mode 0600) without the passphrase's line, for
      android-instrument.sh's usual judge, which prints parts of RAW to the job log and all of it when the
      run fails, so the value never reaches the job log or a file; it is held in this process's memory
      alone, never in an argument, the environment or a file. Then, unless the run holds exactly one of
      each value, well formed (the passphrase 8 words of the BIP39 English list, the name core's
      keepcrypt-backup- and 8 lower-case hex digits and .age, the fingerprint 8 lower-case hex digits), it
      fails with no adb call. It reads the file from the emulator (ADB -s SERIAL exec-out cat
      /sdcard/Download/NAME, at most core's 8 KiB), and has the age CLI (AGE, default: age on PATH; CI:
      Ubuntu's 1.1.1, the local loop Homebrew's) decrypt it through scripts/age-interop.py's pty driver,
      which types the passphrase at age's prompt: the plaintext must be a well-formed KeepCrypt backup
      v1 (tools/verify's reader: words, braille, the fingerprint recomputed from the words) written by
      keepcrypt-android, with the fingerprint the test reported; and a fresh wrong passphrase must be
      refused by age. The ciphertext and the plaintext (the throwaway gate seed's words, public vectors)
      go only to a private temporary directory, removed at the end. Last, the value's reach: logcat -d of
      every buffer (ADB -s SERIAL logcat -d -b all, read into memory) and the run's output must hold
      neither the passphrase whole, nor either page of four words as core gives them, nor two or more of
      the eight lines the passphrase screen draws ("3 word", a page's four in one node, which a log
      would show together; one alone a log can hold by chance, a number and a common word); and the
      run's output (the job log's share of this run) must hold none of its words as a word, outside the
      status keys and the test's kc_probe and kc_pass lines, whose prose is the test's own fixed text
      with public values.
      Prints one line, "age-check: pass (...)" or "age-check: fail: ...", with counts and versions
      only, never a value. Exit 0 pass, 1 fail, 2 bad usage or no age binary.
  scripts/android-age-check.py --selftest [--age AGE]
      Runs this script on stand-ins in a temporary directory: an adb that serves a backup written by
      tools/verify's age writer at work factor 18 and a logcat, and the real age. A run that holds the
      three values passes, with RAW holding no passphrase line and no output a passphrase word, and so
      does one whose logcat holds one of the screen's lines; no passphrase value, two, one that is not
      8 list words, a name that is not core's (no adb call for those three or that), a wrong passphrase,
      another fingerprint, a backup another app wrote, no file on the emulator, the passphrase and two of
      the screen's lines in logcat, a page and a word of it in the run's output each fail; and bad usage
      exits 2. Exit 0 when every case behaves, 1 otherwise. It needs age and
      hashlib.scrypt; it takes about half a minute.
"""

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGE_INTEROP = ROOT / "scripts" / "age-interop.py"

# The status keys (INSTRUMENTATION_STATUS: KEY=VALUE) the backup's emulator test reports.
PASSPHRASE_KEY = "kc_ci_throwaway_passphrase"
NAME_KEY = "kc_backup_name"
FINGERPRINT_KEY = "kc_backup_fingerprint"
STATUS = "INSTRUMENTATION_STATUS: "
# Core's suggested name (core/src/backup.rs) and a fingerprint's hex.
NAME = re.compile(r"keepcrypt-backup-[0-9a-f]{8}\.age")
FINGERPRINT = re.compile(r"[0-9a-f]{8}")
# Where the system's picker saved the file on the emulator: the Downloads root.
DOWNLOADS = "/sdcard/Download/"
# The test's own prose, its probe and pass lines, which the word search leaves out.
PROSE_KEYS = ("kc_probe", "kc_pass")
ADB_TIMEOUT_SECONDS = 120


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Fail(Exception):
    """A check that failed; its text names it, never a value."""


def status_value(line, key):
    """The value of a status line for key, or None."""
    prefix = STATUS + key + "="
    return line[len(prefix):] if line.startswith(prefix) else None


def split_run(raw):
    """(the run without the passphrase's lines, the passphrase values, the name values, the fingerprint values)."""
    kept, passphrases, names, fingerprints = [], [], [], []
    for line in raw.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        value = status_value(bare, PASSPHRASE_KEY)
        if value is not None:
            passphrases.append(value)
            continue
        for key, values in ((NAME_KEY, names), (FINGERPRINT_KEY, fingerprints)):
            found = status_value(bare, key)
            if found is not None:
                values.append(found)
        kept.append(line)
    return "".join(kept), passphrases, names, fingerprints


def one(values, what):
    if len(values) != 1:
        raise Fail("%d %s values in the run's output (exactly one is needed)" % (len(values), what))
    return values[0]


def needles(words):
    """What would show the passphrase alone: whole, and each page of four as core gives it."""
    return [" ".join(words), " ".join(words[:4]), " ".join(words[4:])]


def drawn_lines(words):
    """The eight lines the passphrase screen draws, "3 word", two or more of which would show a page."""
    return ["%d %s" % (number, word) for number, word in enumerate(words, 1)]


def prose_free(stripped):
    """The run's output for the word search: the status lines' values with their keys removed, and every other
    line as it is, the test's kc_probe and kc_pass lines left out."""
    lines = []
    for line in stripped.splitlines():
        if line.startswith(STATUS):
            key, _, value = line[len(STATUS):].partition("=")
            if key in PROSE_KEYS:
                continue
            lines.append(value)
        else:
            lines.append(line)
    return "\n".join(lines)


def word_hits(text, words):
    """How many times any of words stands in text as a word (letters on neither side)."""
    return sum(len(re.findall(r"(?<![A-Za-z])" + re.escape(word) + r"(?![A-Za-z])", text)) for word in words)


def adb_bytes(adb, serial, args):
    run = subprocess.run([adb, "-s", serial] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=ADB_TIMEOUT_SECONDS)
    if run.returncode != 0:
        raise Fail("adb %s exited %d" % (args[0], run.returncode))
    return run.stdout


def check(raw, raw_path, adb, serial, age, interop, verify):
    """The hand-off's checks; returns the pass line, or raises Fail. RAW is written first, whatever follows."""
    stripped, passphrases, names, fingerprints = split_run(raw)
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        out.write(stripped)
    value = one(passphrases, "passphrase")
    name = one(names, "backup name")
    fingerprint = one(fingerprints, "fingerprint")
    words = value.split(" ")
    if len(words) != 8 or any(word not in verify.BIP39_ENGLISH for word in words):
        raise Fail("the passphrase value is not 8 words of the BIP39 English list")
    if not NAME.fullmatch(name):
        raise Fail("the backup name is not core's (keepcrypt-backup-, 8 hex digits, .age)")
    if not FINGERPRINT.fullmatch(fingerprint):
        raise Fail("the fingerprint is not 8 lower-case hex digits")
    data = adb_bytes(adb, serial, ["exec-out", "cat", DOWNLOADS + name])
    if not 0 < len(data) <= verify.BACKUP_MAX_FILE_BYTES:
        raise Fail("the file read from the emulator holds %d bytes, not 1 to %d" % (len(data), verify.BACKUP_MAX_FILE_BYTES))
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        os.chmod(tmp, 0o700)
        source, target = work / "backup.age", work / "plaintext"
        source.write_bytes(data)
        code, answered, _ = interop.run_age(age, ["-d", "-o", str(target), str(source)], [value.encode("ascii")])
        if code != 0 or answered != 1 or not target.is_file():
            raise Fail("age -d did not decrypt the backup with the passphrase (exit %d after %d prompts)" % (code, answered))
        plaintext = target.read_bytes()
        wrong = interop.fresh_passphrase(verify)
        refused, _, _ = interop.run_age(age, ["-d", "-o", str(work / "wrong"), str(source)], [wrong])
        if refused == 0 or (work / "wrong").exists() and (work / "wrong").stat().st_size > 0:
            raise Fail("age -d accepted a wrong passphrase")
    try:
        backup_words, backup_fingerprint, app, version = verify.backup_plaintext_parse(plaintext)
    except verify.BackupRefused as refusal:
        raise Fail("the decrypted text is not a KeepCrypt backup v1 (%s)" % refusal.error)
    if app != "android":
        raise Fail("the backup was written by keepcrypt-%s, not keepcrypt-android" % app)
    if backup_fingerprint.hex() != fingerprint:
        raise Fail("the backup's fingerprint is not the one the test reported")
    log = adb_bytes(adb, serial, ["logcat", "-d", "-b", "all"]).decode("utf-8", "replace")
    for text, where in ((log, "logcat -d"), (stripped, "the run's output")):
        whole = sum(text.count(needle) for needle in needles(words))
        if whole:
            raise Fail("%s holds the passphrase or a page of it %d time(s)" % (where, whole))
        lines = sum(1 for line in drawn_lines(words) if line in text)
        if lines >= 2:
            raise Fail("%s holds %d of the 8 lines the passphrase screen draws" % (where, lines))
    loose = word_hits(prose_free(stripped), words)
    if loose:
        raise Fail("the run's output holds a word of the passphrase %d time(s), outside the test's own prose" % loose)
    return ("age-check: pass (%s): age -d through the pty decrypted the backup (%d bytes) to a KeepCrypt backup v1 of "
            "%d words by keepcrypt-android %d.%d.%d with the fingerprint the test reported, and refused a wrong "
            "passphrase; neither logcat -d (%d characters) nor the run's output (%d lines) holds the passphrase, a "
            "page of it or two of its screen's lines, nor the output a word of it"
            % ((interop.age_version(age), len(data), len(backup_words)) + tuple(version)
               + (len(log), len(stripped.splitlines()))))


def run(args):
    age = shutil.which(args.age)
    if age is None:
        print("age-check: no age binary %r" % args.age, file=sys.stderr)
        return 2
    interop = load("keepcrypt_age_interop", AGE_INTEROP)
    verify = interop.load_verify()
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        print(check(raw, args.raw, args.adb, args.serial, age, interop, verify))
        return 0
    except (Fail, OSError, subprocess.SubprocessError) as problem:
        text = str(problem) if isinstance(problem, Fail) else type(problem).__name__
        print("age-check: fail: %s" % text)
        return 1


# --- The selftest -------------------------------------------------------------------------------------

STUB_ADB = r'''#!/usr/bin/env python3
"""The selftest's stand-in adb: -s SERIAL exec-out cat PATH serves the case's file, logcat -d -b all its log;
every call is recorded."""
import os
import sys
case = os.environ["KC_STUB"]
with open(os.path.join(case, "calls"), "a") as calls:
    calls.write(" ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:2] != ["-s", "emulator-5554"]:
    sys.exit(1)
if args[2:4] == ["exec-out", "cat"] and len(args) == 5:
    path = os.path.join(case, "device", os.path.basename(args[4]))
    if not os.path.isfile(path):
        sys.exit(1)
    with open(path, "rb") as f:
        sys.stdout.buffer.write(f.read())
elif args[2:] == ["logcat", "-d", "-b", "all"]:
    with open(os.path.join(case, "logcat"), "rb") as f:
        sys.stdout.buffer.write(f.read())
else:
    sys.exit(1)
'''

# The selftest's passphrase: words of the list that none of this script's messages holds.
SELF_WORDS = ["zebra", "yellow", "youth", "wrist", "wreck", "worth", "wolf", "zoo"]
SELF_NAME = "keepcrypt-backup-0a1b2c3d.age"
SELF_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def self_run(name, passphrase=None, names=(SELF_NAME,), fingerprint=None, extra=""):
    """An am instrument -r run of the backup's test, its three values reported (one passphrase line per value
    of passphrase), CRLF line ends as adb gives them."""
    lines = ["INSTRUMENTATION_STATUS: class=com.keepcrypt.entropy.BackupTest", "INSTRUMENTATION_STATUS: current=1",
             "INSTRUMENTATION_STATUS: id=AndroidJUnitRunner", "INSTRUMENTATION_STATUS: numtests=1",
             "INSTRUMENTATION_STATUS: stream=", "INSTRUMENTATION_STATUS: test=aBackupSavedToDownloads",
             "INSTRUMENTATION_STATUS_CODE: 1",
             "INSTRUMENTATION_STATUS: kc_probe=this test saved the file once, at the time it took",
             "INSTRUMENTATION_STATUS_CODE: 2"]
    for value in passphrase if passphrase is not None else [" ".join(SELF_WORDS)]:
        lines += ["INSTRUMENTATION_STATUS: %s=%s" % (PASSPHRASE_KEY, value), "INSTRUMENTATION_STATUS_CODE: 2"]
    for value in names:
        lines += ["INSTRUMENTATION_STATUS: %s=%s" % (NAME_KEY, value), "INSTRUMENTATION_STATUS_CODE: 2"]
    lines += ["INSTRUMENTATION_STATUS: %s=%s" % (FINGERPRINT_KEY, fingerprint), "INSTRUMENTATION_STATUS_CODE: 2"]
    lines += extra.splitlines()
    lines += ["INSTRUMENTATION_STATUS: class=com.keepcrypt.entropy.BackupTest", "INSTRUMENTATION_STATUS: current=1",
              "INSTRUMENTATION_STATUS: stream=.", "INSTRUMENTATION_STATUS: test=aBackupSavedToDownloads",
              "INSTRUMENTATION_STATUS_CODE: 0", "INSTRUMENTATION_RESULT: stream=", "", "Time: 9.8", "", "OK (1 test)",
              "", "", "INSTRUMENTATION_CODE: -1"]
    return "".join(line + "\r\n" for line in lines)


def selftest(args):
    age = shutil.which(args.age)
    if age is None:
        print("age-check selftest: no age binary %r" % args.age, file=sys.stderr)
        return 2
    interop = load("keepcrypt_age_interop", AGE_INTEROP)
    verify = interop.load_verify()
    if not hasattr(verify.hashlib, "scrypt"):
        print("age-check selftest: this Python's hashlib has no scrypt", file=sys.stderr)
        return 2
    words = SELF_MNEMONIC.split(" ")
    fingerprint = verify.backup_fingerprint(words)

    def backup(app):
        plaintext = verify.backup_plaintext(words, fingerprint, app, (0, 0, 0)).encode("utf-8")
        return verify.age_armor(verify.age_encrypt(" ".join(SELF_WORDS).encode("ascii"), os.urandom(16), os.urandom(16),
                                                   os.urandom(16), verify.BACKUP_WORK_FACTOR, plaintext))

    android, pi = backup("android"), backup("pi")
    passed, failed = 0, 0
    with tempfile.TemporaryDirectory() as tmp:
        st = Path(tmp)
        adb = st / "adb"
        adb.write_text(STUB_ADB, encoding="ascii")
        adb.chmod(0o755)

        def case(label, want, texts, run_text, file=android, log="I ActivityManager: Start proc 4242\n", calls=None):
            nonlocal passed, failed
            directory = st / label
            (directory / "device").mkdir(parents=True)
            if file is not None:
                (directory / "device" / SELF_NAME).write_bytes(file)
            (directory / "logcat").write_text(log, encoding="utf-8")
            (directory / "calls").write_text("", encoding="ascii")
            raw_path = directory / "raw"
            done = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--raw", str(raw_path), str(adb),
                                   "emulator-5554", "--age", age], input=run_text.encode("utf-8"), capture_output=True,
                                  env=dict(os.environ, KC_STUB=str(directory)), timeout=600)
            out = (done.stdout + done.stderr).decode("utf-8", "replace")
            stripped = raw_path.read_text(encoding="utf-8") if raw_path.exists() else ""
            problems = []
            if done.returncode != want:
                problems.append("exit %d, wanted %d" % (done.returncode, want))
            problems += ["no %r" % text for text in texts if text not in out]
            if word_hits(out, SELF_WORDS):
                problems.append("the output holds a passphrase word")
            if want != 2 and (PASSPHRASE_KEY in stripped or " ".join(SELF_WORDS[:4]) in stripped):
                problems.append("RAW holds the passphrase's line")
            if calls is not None and (directory / "calls").read_text(encoding="ascii").strip() != calls:
                problems.append("adb calls: %r" % (directory / "calls").read_text(encoding="ascii"))
            if problems:
                failed += 1
                print("FAIL %s: %s" % (label, "; ".join(problems)))
                print("".join("  | %s\n" % line for line in out.splitlines()), end="")
            else:
                passed += 1
                print("PASS %s" % label)

        good = fingerprint.hex()
        # The test's own prose may hold a list word that the passphrase holds too: its kc_pass line is left out.
        case("pass", 0, ["age-check: pass (", "refused a wrong passphrase", "by keepcrypt-android 0.0.0"],
             self_run("pass", fingerprint=good, extra="INSTRUMENTATION_STATUS: kc_pass=a %s strip, then the file\n"
                      "INSTRUMENTATION_STATUS_CODE: 2" % SELF_WORDS[1]))
        case("no-passphrase", 1, ["0 passphrase values"], self_run("none", passphrase=[], fingerprint=good), calls="")
        case("two-passphrases", 1, ["2 passphrase values"],
             self_run("two", passphrase=[" ".join(SELF_WORDS)] * 2, fingerprint=good), calls="")
        case("not-list-words", 1, ["not 8 words of the BIP39 English list"],
             self_run("words", passphrase=[" ".join(SELF_WORDS[:7] + ["qqqq"])], fingerprint=good), calls="")
        case("seven-words", 1, ["not 8 words"], self_run("seven", passphrase=[" ".join(SELF_WORDS[:7])], fingerprint=good),
             calls="")
        case("not-cores-name", 1, ["not core's"], self_run("name", names=["../keepcrypt-backup-0a1b2c3d.age"], fingerprint=good),
             calls="")
        case("wrong-passphrase", 1, ["age -d did not decrypt"],
             self_run("wrong", passphrase=[" ".join(reversed(SELF_WORDS))], fingerprint=good))
        case("another-fingerprint", 1, ["not the one the test reported"], self_run("fp", fingerprint="00000000"))
        case("another-app", 1, ["written by keepcrypt-pi"], self_run("app", fingerprint=good), file=pi)
        case("no-file", 1, ["adb exec-out exited 1"], self_run("nofile", fingerprint=good), file=None)
        case("passphrase-in-logcat", 1, ["logcat -d holds the passphrase or a page"], self_run("log", fingerprint=good),
             log="I ActivityManager: status kc=%s\n" % " ".join(SELF_WORDS))
        case("two-lines-in-logcat", 1, ["logcat -d holds 2 of the 8 lines"], self_run("lines", fingerprint=good),
             log="D UiAutomator: Skipping invisible child: text: 1 %s\nD UiAutomator: 2 %s\n" % (SELF_WORDS[0], SELF_WORDS[1]))
        case("one-line-in-logcat", 0, ["age-check: pass ("], self_run("line", fingerprint=good),
             log="I Something: retry 3 %s later\n" % SELF_WORDS[2])
        case("page-in-the-run", 1, ["the run's output holds the passphrase or a page"],
             self_run("page", fingerprint=good, extra="INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: %s"
                      % " ".join(SELF_WORDS[4:])))
        case("word-in-the-run", 1, ["holds a word of the passphrase"],
             self_run("word", fingerprint=good, extra="INSTRUMENTATION_STATUS: stack=expected:<%s>" % SELF_WORDS[0]))
        usage = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--raw"], capture_output=True, timeout=60)
        if usage.returncode == 2:
            passed += 1
            print("PASS bad usage")
        else:
            failed += 1
            print("FAIL bad usage: exit %d" % usage.returncode)
    print("android-age-check selftest: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


def main(argv):
    if argv[:1] == ["--selftest"]:
        parser = argparse.ArgumentParser(prog="android-age-check.py --selftest")
        parser.add_argument("--selftest", action="store_true")
        parser.add_argument("--age", default="age")
        return selftest(parser.parse_args(argv))
    parser = argparse.ArgumentParser(prog="android-age-check.py", description="The CI age -d hand-off for the backup.")
    parser.add_argument("--raw", required=True, help="where the run, without the passphrase's line, is written")
    parser.add_argument("--age", default="age", help="the age binary (default: age on PATH)")
    parser.add_argument("adb")
    parser.add_argument("serial")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
