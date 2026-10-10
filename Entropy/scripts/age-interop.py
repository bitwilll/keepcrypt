#!/usr/bin/env python3
"""age CLI interop for the KeepCrypt backup (tasks/todo.md, M1 group 8 and Q1 ii).

Python 3.9+, standard library only. It drives the age CLI through a pseudo-terminal, since age reads a
passphrase only from the terminal, and checks the age CLI against the age code in tools/verify/, verify.py's
reader and vectorgen.py's writer (the same bytes core reads and writes; check 11 holds the two together):

  scripts/age-interop.py [--age PATH]             both directions, live, at work factor 18:
      - age -> KeepCrypt: age encrypts each backup.json plaintext (armored and binary) under a fresh
        8-word passphrase, and verify.py's reader decrypts it to the same bytes;
      - KeepCrypt -> age: vectorgen.py's writer encrypts each plaintext (armored, work factor 18, fresh
        file key, salt and nonce), and age decrypts it to the same bytes;
      - a wrong passphrase fails in age (non-zero exit, no output) and in the reader (WrongPassphrase);
      - every file in vectors/age/age_cli_written.json decrypts in the reader and in age;
      - every age file in vectors/backup.json that the readers accept (the written files and the reader-only
        armor variants) decrypts in age to its plaintext, so core and verify.py accept no file age refuses.
        Each armor case the readers refuse (Backup(Armor)) is also given to age; one that age accepts is
        printed as a note, not a failure, since a stricter reader is safe.
  scripts/age-interop.py --core [--age PATH]      all of the above, and core in both directions: age
      encrypts each plaintext (armored and binary) under a fresh passphrase and core's decrypt_backup
      reads it; core writes a fresh backup of each (work factor 18, its own OS randomness) and age
      decrypts it to backup.json's plaintext; a wrong passphrase fails in age. Core's side is the
      ignored unit test backup::tests::age_interop_files, run through `cargo test` with
      KC_AGE_INTEROP_DIR naming a temporary directory, so this needs the Rust toolchain.
  scripts/age-interop.py --generate [--age PATH]  write vectors/age/age_cli_written.json: age's own armored
      and binary files of the abandon-12 and zoo-24 plaintexts, under backup.json's passphrases, after
      checking that the reader decrypts each. Run once; vectors/SOURCES.md records the tool and its hash.

The live run needs hashlib.scrypt (OpenSSL), since work factor 18 is far too slow in pure Python. Fresh
passphrases and keys come from os.urandom (docs/design.md: "In Python use os.urandom or secrets only");
the plaintexts are public test mnemonics. Exit codes: 0 all good, 1 a check failed, 2 usage or
environment error (no age, no hashlib.scrypt).
"""

import argparse
import importlib.util
import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORGEN_PY = ROOT / "tools" / "verify" / "vectorgen.py"
VECTORS = ROOT / "vectors"
CLI_VECTORS = VECTORS / "age" / "age_cli_written.json"
AGE_TIMEOUT_SECONDS = 120
# The plaintexts exchanged with age, and the backup.json passphrase each committed file uses.
PLAINTEXTS = ("abandon-12", "zoo-24")


def load_verify():
    """tools/verify/vectorgen.py as a module, loaded by path: verify.py's names, the age reader among them,
    and the writer and passphrase helpers that build vectors (age_encrypt, age_armor)."""
    spec = importlib.util.spec_from_file_location("keepcrypt_vectorgen", VECTORGEN_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_age(age, args, answers):
    """Run `age args` on a pseudo-terminal, typing answers[i] at the i-th passphrase prompt. Returns
    (exit code, prompts answered, what age wrote to the terminal)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv(age, [age] + args)
        finally:
            os._exit(127)
    transcript, pending, answered = b"", b"", 0
    deadline = time.monotonic() + AGE_TIMEOUT_SECONDS
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:  # EIO: age closed the terminal
                break
            if not chunk:
                break
            transcript += chunk
            pending += chunk
            if answered < len(answers) and b"assphrase" in pending and pending.rstrip().endswith(b":"):
                os.write(fd, answers[answered] + b"\n")
                answered += 1
                pending = b""
        else:
            os.kill(pid, signal.SIGKILL)
    finally:
        os.close(fd)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), answered, transcript.decode("utf-8", "replace")


def age_encrypt_file(age, passphrase, plaintext, armored, workdir, name):
    """age -e -p [-a] of `plaintext`; the file's bytes, or raise RuntimeError."""
    source, target = workdir / (name + ".txt"), workdir / (name + ".age")
    source.write_bytes(plaintext)
    code, answered, transcript = run_age(age, ["-e", "-p"] + (["-a"] if armored else []) + ["-o", str(target), str(source)],
                                         [passphrase, passphrase])
    if code != 0 or answered != 2 or not target.is_file():
        raise RuntimeError("age -e %s: exit %d after %d prompts: %s" % (name, code, answered, transcript.strip()[-300:]))
    return target.read_bytes()


def age_decrypt_file(age, passphrase, data, workdir, name):
    """age -d of `data`: (exit code, the plaintext or None)."""
    source, target = workdir / (name + ".in.age"), workdir / (name + ".out")
    source.write_bytes(data)
    code, _, _ = run_age(age, ["-d", "-o", str(target), str(source)], [passphrase])
    return code, (target.read_bytes() if target.is_file() else None)


def fresh_passphrase(verify):
    """A fresh 8-word passphrase from 11 OS bytes, as core draws one."""
    return verify.backup_passphrase_text(verify.backup_passphrase_indices(os.urandom(11))).encode("ascii")


def backup_doc():
    return json.loads((VECTORS / "backup.json").read_text(encoding="ascii"))


def plaintext_texts(doc):
    return {case["name"]: case["text"].encode("utf-8") for case in doc["plaintexts"]}


def case_bytes(case):
    """The bytes of a vectors entry: armored text in "file", anything else in "file_hex"."""
    return case["file"].encode("utf-8") if "file" in case else bytes.fromhex(case["file_hex"])


def reader_gives(verify, data, passphrase):
    """The reader's plaintext, or the name of its error."""
    try:
        return verify.age_decrypt(data, passphrase)
    except verify.BackupRefused as refused:
        return refused.error


def age_version(age):
    run = subprocess.run([age, "--version"], capture_output=True, encoding="utf-8", timeout=30)
    return run.stdout.strip()


def check_live(verify, age, workdir):
    """Both directions, live, plus the wrong passphrase and the committed files. Returns problems."""
    problems = []
    texts = plaintext_texts(backup_doc())
    for name in PLAINTEXTS:
        plaintext, passphrase, wrong = texts[name], fresh_passphrase(verify), fresh_passphrase(verify)
        for armored in (True, False):
            label = "%s-%s" % (name, "armored" if armored else "binary")
            data = age_encrypt_file(age, passphrase, plaintext, armored, workdir, "cli-" + label)
            if reader_gives(verify, data, passphrase) != plaintext:
                problems.append("age -> KeepCrypt %s: the reader gives %r" % (label, reader_gives(verify, data, passphrase)))
            if reader_gives(verify, data, wrong) != "WrongPassphrase":
                problems.append("age -> KeepCrypt %s: a wrong passphrase is not refused" % label)
        data = verify.age_armor(verify.age_encrypt(passphrase, os.urandom(16), os.urandom(16), os.urandom(16),
                                                   verify.BACKUP_WORK_FACTOR, plaintext))
        code, out = age_decrypt_file(age, passphrase, data, workdir, "ref-" + name)
        if code != 0 or out != plaintext:
            problems.append("KeepCrypt -> age %s: age exits %d, plaintext %s" % (name, code, "equal" if out == plaintext else "differs"))
        code, out = age_decrypt_file(age, wrong, data, workdir, "ref-wrong-" + name)
        if code == 0 or out is not None:
            problems.append("KeepCrypt -> age %s: age accepted a wrong passphrase (exit %d)" % (name, code))
    committed = json.loads(CLI_VECTORS.read_text(encoding="ascii"))
    for case in committed["files"]:
        data = case_bytes(case)
        passphrase = case["passphrase"].encode("ascii")
        if reader_gives(verify, data, passphrase) != texts[case["plaintext"]]:
            problems.append("%s %s: the reader does not decrypt it" % (CLI_VECTORS.name, case["name"]))
        code, out = age_decrypt_file(age, passphrase, data, workdir, "committed-" + case["name"])
        if code != 0 or out != texts[case["plaintext"]]:
            problems.append("%s %s: age does not decrypt it (exit %d)" % (CLI_VECTORS.name, case["name"], code))
    return problems


def check_backup_json_files(age, workdir):
    """backup.json's age files through age: every file the readers accept must decrypt to its plaintext.
    Returns (problems, notes, how many age_files, how many armor refusals age also refuses, how many armor
    refusals)."""
    doc = backup_doc()
    texts = plaintext_texts(doc)
    problems, notes = [], []
    for case in doc["age_files"]:
        plaintext = texts[case["plaintext"]] if "plaintext" in case else bytes.fromhex(case["plaintext_hex"])
        code, out = age_decrypt_file(age, case["passphrase"].encode("ascii"), case_bytes(case), workdir,
                                     "vector-" + case["name"])
        if code != 0 or out != plaintext:
            problems.append("backup.json age_files %s: the readers accept it, age exits %d, plaintext %s"
                            % (case["name"], code, "equal" if out == plaintext else "differs"))
    armor = [case for case in doc["age_refused"] if case["error"] == "Backup(Armor)"]
    refused_too = 0
    for case in armor:
        code, out = age_decrypt_file(age, case["passphrase"].encode("ascii"), case_bytes(case), workdir,
                                     "refused-" + case["name"])
        if code == 0 or out is not None:
            notes.append("age accepts backup.json age_refused %s, which the readers refuse as Backup(Armor)"
                         % case["name"])
        else:
            refused_too += 1
    return problems, notes, len(doc["age_files"]), refused_too, len(armor)


def check_core(verify, age, workdir):
    """Core in both directions, through its ignored age_interop_files test. Returns problems."""
    doc = backup_doc()
    texts = plaintext_texts(doc)
    mnemonics = {case["name"]: case["mnemonic"] for case in doc["plaintexts"]}
    exchange = workdir / "exchange"
    exchange.mkdir()
    for name in PLAINTEXTS:
        passphrase = fresh_passphrase(verify)
        for armored in (True, False):
            label = "%s-%s" % (name, "armored" if armored else "binary")
            data = age_encrypt_file(age, passphrase, texts[name], armored, workdir, "plain-" + label)
            (exchange / ("cli-%s.age" % label)).write_bytes(data)
            (exchange / ("cli-%s.words" % label)).write_bytes(passphrase)
            (exchange / ("cli-%s.mnemonic" % label)).write_text(mnemonics[name], encoding="ascii")
    run = subprocess.run(
        ["cargo", "test", "-p", "keepcrypt-core", "--locked", "--lib", "--", "--ignored", "--exact",
         "backup::tests::age_interop_files"],
        cwd=str(ROOT), env=dict(os.environ, KC_AGE_INTEROP_DIR=str(exchange)), capture_output=True,
        encoding="utf-8", errors="replace", timeout=1800)
    if run.returncode != 0 or "1 passed" not in run.stdout:
        return ["core: age_interop_files failed (exit %d): %s" % (run.returncode, (run.stdout + run.stderr).strip()[-600:])]
    problems = []
    for name in PLAINTEXTS:
        data = (exchange / ("core-%s.age" % name)).read_bytes()
        words = (exchange / ("core-%s.words" % name)).read_bytes()
        stanzas, _, _, _ = verify.age_parse_header(verify.age_dearmor(data))
        if verify.age_scrypt_stanza(stanzas)[1] != verify.BACKUP_WORK_FACTOR:
            problems.append("core -> age %s: not work factor %d" % (name, verify.BACKUP_WORK_FACTOR))
        code, out = age_decrypt_file(age, words, data, workdir, "core-read-" + name)
        if code != 0 or out != texts[name]:
            problems.append("core -> age %s: age exits %d, plaintext %s" % (name, code, "equal" if out == texts[name] else "differs"))
        code, out = age_decrypt_file(age, fresh_passphrase(verify), data, workdir, "core-wrong-" + name)
        if code == 0 or out is not None:
            problems.append("core -> age %s: age accepted a wrong passphrase (exit %d)" % (name, code))
    return problems


def generate(verify, age, workdir):
    """Write vectors/age/age_cli_written.json from age's own files."""
    doc = backup_doc()
    texts = plaintext_texts(doc)
    passphrases = {"abandon-12": next(p for p in doc["passphrases"] if p["name"] == "stream")["passphrase"],
                   "zoo-24": next(g for g in doc["generate"] if g["name"] == "stream")["passphrase"]}
    files = []
    for name in PLAINTEXTS:
        passphrase = passphrases[name].encode("ascii")
        for armored in (True, False):
            label = "%s-%s" % (name, "armored" if armored else "binary")
            data = age_encrypt_file(age, passphrase, texts[name], armored, workdir, label)
            if reader_gives(verify, data, passphrase) != texts[name]:
                raise RuntimeError("the reader does not decrypt age's %s" % label)
            case = {"name": label, "plaintext": name, "passphrase": passphrases[name], "armored": armored}
            case.update({"file": data.decode("ascii")} if armored else {"file_hex": data.hex()})
            files.append(case)
    out = {
        "description": "Files written by the age CLI (scripts/age-interop.py --generate), armored and binary, of "
        "backup.json's abandon-12 and zoo-24 plaintexts under backup.json's passphrases (passphrases 'stream' and "
        "generate 'stream'), at age's own work factor 18. Core's tests and scripts/age-interop.py decrypt them; "
        "verify.py --selftest reads their armor and headers (check 11). vectors/SOURCES.md records the tool.",
        "tool_version": age_version(age),
        "files": files,
    }
    CLI_VECTORS.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    print("wrote %s with %s" % (CLI_VECTORS, out["tool_version"]))


def main(argv):
    parser = argparse.ArgumentParser(prog="age-interop.py", description="age CLI interop for the KeepCrypt backup.")
    parser.add_argument("--age", default="age", help="the age binary (default: age on PATH)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--generate", action="store_true", help="write vectors/age/age_cli_written.json")
    mode.add_argument("--core", action="store_true", help="also run core in both directions (needs cargo)")
    args = parser.parse_args(argv)
    age = shutil.which(args.age)
    if age is None:
        print("age-interop: no age binary %r" % args.age, file=sys.stderr)
        return 2
    verify = load_verify()
    if not hasattr(verify.hashlib, "scrypt"):
        print("age-interop: this Python's hashlib has no scrypt; work factor 18 needs it", file=sys.stderr)
        return 2
    print("age-interop: %s" % age_version(age))
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        try:
            if args.generate:
                generate(verify, age, workdir)
                return 0
            problems = check_live(verify, age, workdir)
            vector_problems, notes, accepted, refused_too, armor = check_backup_json_files(age, workdir)
            problems += vector_problems
            if args.core:
                problems += check_core(verify, age, workdir)
        except (RuntimeError, OSError, subprocess.SubprocessError, verify.BackupRefused) as e:
            print("age-interop: FAIL: %s" % e)
            return 1
    for note in notes:
        print("note: %s" % note)
    for problem in problems:
        print("FAIL %s" % problem)
    if problems:
        return 1
    print("age-interop: ok: age -> KeepCrypt and KeepCrypt -> age at work factor 18, armored and binary; wrong "
          "passphrases refused by both; %s decrypted by both" % CLI_VECTORS.name)
    print("age-interop: ok: age decrypted all %d backup.json age files the readers accept, and also refused %d of "
          "the %d armor cases they refuse" % (accepted, refused_too, armor))
    if args.core:
        print("age-interop: ok: core read age's files (decrypt_backup), age read core's fresh work-factor-18 "
              "backups, and age refused a wrong passphrase")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
